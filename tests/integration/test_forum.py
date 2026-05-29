# -*- coding: utf-8 -*-
"""forum_routes.py 集成测试（§4j）：论坛列表 / 发帖 / 看帖 / 回帖 + Markdown 渲染。

源码事实（oj_modules/routes/forum_routes.py）：
- `forum_index` GET `/forum` —— 列表页，渲染 forum_index.html。
- `create_thread` GET/POST `/forum/new` —— 未登录重定向到 auth.login（非 403）；
  POST 时 title/content `.strip()` 后任一为空 → flash('标题和内容不能为空','danger') + 重定向回
  create_thread；成功 → INSERT forum_threads + flash('帖子创建成功','success') + 重定向 forum_index。
- `view_thread` GET/POST `/forum/thread/<id>` —— thread/replies 的 content 经
  render_markdown_with_highlighting() 渲染后传模板；POST 空回复 flash('回复内容不能为空')。
- `reply_thread` POST `/forum/reply/<id>` —— 未登录重定向到 auth.login；成功 INSERT forum_replies
  + flash('回复成功','success') + 重定向 view_thread。

约定：DB 每个用例前 truncate+reseed（admin / Cclass1 等）。flash 文案在 follow_redirects
后渲染进页面，可按字节断言；DB 为真相来源，用 SQL 读回校验入库。
"""
from oj_modules import db_services as db
from oj_modules.routes import forum_routes
from tests import helpers


# --------------------------- DB helpers ---------------------------

def _make_thread(title='标题', content='正文', user_id=None):
    """直接入库一条帖子，返回 thread id。"""
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO forum_threads (title, content, user_id) VALUES (%s,%s,%s)",
                (title, content, user_id),
            )
            tid = cur.lastrowid
        conn.commit()
    finally:
        conn.close()
    return tid


def _count(table):
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) AS n FROM {table}")
            return cur.fetchone()['n']
    finally:
        conn.close()


def _threads():
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM forum_threads ORDER BY id ASC")
            return cur.fetchall()
    finally:
        conn.close()


def _replies(thread_id):
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM forum_replies WHERE thread_id=%s ORDER BY id ASC",
                (thread_id,),
            )
            return cur.fetchall()
    finally:
        conn.close()


# --------------------------- /forum 列表 ---------------------------

def test_forum_index_ok_empty(client):
    """空论坛也应正常 200（admin 用户存在但无帖子）。"""
    r = client.get('/forum')
    assert r.status_code == 200


def test_forum_index_lists_threads(client, admin_login):
    admin = db.get_user_by_username(admin_login)
    _make_thread(title='第一帖标题ABC', content='hello', user_id=admin['id'])
    r = client.get('/forum')
    assert r.status_code == 200
    assert '第一帖标题ABC'.encode() in r.data


# --------------------------- 未登录发帖（重定向到登录，不入库）---------------------------

def test_create_thread_requires_login_redirect(client):
    """源码：未登录 POST /forum/new 重定向到 auth.login，且不写库。"""
    r = client.post('/forum/new', data={'title': '标题', 'content': '正文'})
    assert r.status_code in (301, 302)
    assert '/login' in r.headers.get('Location', '')
    assert _count('forum_threads') == 0


def test_reply_requires_login_redirect(client, admin_login):
    """未登录回帖：先用 admin 造帖，再以匿名 client POST，重定向到 login 且不写 reply。"""
    admin = db.get_user_by_username(admin_login)
    tid = _make_thread(user_id=admin['id'])
    # 清掉登录态，模拟匿名
    with client.session_transaction() as sess:
        sess.clear()
    r = client.post(f'/forum/reply/{tid}', data={'content': '匿名回复'})
    assert r.status_code in (301, 302)
    assert '/login' in r.headers.get('Location', '')
    assert _count('forum_replies') == 0


# --------------------------- 建帖：空标题 / 空正文拒绝 ---------------------------

def test_create_thread_empty_title_rejected(client, admin_login):
    r = client.post('/forum/new',
                    data={'title': '   ', 'content': '有正文'},
                    follow_redirects=True)
    assert r.status_code == 200
    assert '标题和内容不能为空'.encode() in r.data
    assert _count('forum_threads') == 0


def test_create_thread_empty_content_rejected(client, admin_login):
    r = client.post('/forum/new',
                    data={'title': '有标题', 'content': '  '},
                    follow_redirects=True)
    assert r.status_code == 200
    assert '标题和内容不能为空'.encode() in r.data
    assert _count('forum_threads') == 0


# --------------------------- 建帖：成功入库 + flash ---------------------------

def test_create_thread_success_persists(client, admin_login):
    admin = db.get_user_by_username(admin_login)
    r = client.post('/forum/new',
                    data={'title': '我的新帖', 'content': '帖子正文内容'})
    # 成功后重定向到论坛首页
    assert r.status_code in (301, 302)
    assert '/forum' in r.headers.get('Location', '')

    rows = _threads()
    assert len(rows) == 1
    assert rows[0]['title'] == '我的新帖'
    assert rows[0]['content'] == '帖子正文内容'
    assert rows[0]['user_id'] == admin['id']

    # 跟随重定向到首页应能看到 flash 与帖子标题
    r2 = client.get('/forum')
    assert r2.status_code == 200
    assert '我的新帖'.encode() in r2.data


def test_create_thread_success_flash(client, admin_login):
    r = client.post('/forum/new',
                    data={'title': '另一个帖', 'content': '正文'},
                    follow_redirects=True)
    assert r.status_code == 200
    assert '帖子创建成功'.encode() in r.data


# --------------------------- 查看帖 + Markdown 渲染 ---------------------------

def test_view_thread_404ish_redirects_when_missing(client):
    """不存在的帖子：flash('帖子不存在') 并重定向到论坛首页。"""
    r = client.get('/forum/thread/999999')
    assert r.status_code in (301, 302)
    assert '/forum' in r.headers.get('Location', '')


def test_view_thread_renders_markdown(client, admin_login):
    admin = db.get_user_by_username(admin_login)
    tid = _make_thread(title='MD帖',
                       content='# 大标题\n\n正文里有 **加粗**。',
                       user_id=admin['id'])
    r = client.get(f'/forum/thread/{tid}')
    assert r.status_code == 200
    # Markdown 渲染：# → <h1>，**x** → <strong>
    assert b'<h1' in r.data
    assert b'<strong>' in r.data


def test_render_markdown_fenced_code_highlight():
    """render_markdown_with_highlighting：围栏代码块经 codehilite 产出高亮容器。"""
    html = forum_routes.render_markdown_with_highlighting(
        "```python\nprint('hi')\n```")
    # fenced_code + codehilite 输出 <div class="codehilite"> 与 <pre>
    assert 'codehilite' in html
    assert '<pre' in html


# --------------------------- 回帖（POST view_thread / reply_thread）---------------------------

def test_view_thread_post_reply_persists_and_renders(client, admin_login):
    admin = db.get_user_by_username(admin_login)
    tid = _make_thread(user_id=admin['id'])
    r = client.post(f'/forum/thread/{tid}',
                    data={'content': '回复正文 **粗体**'})
    assert r.status_code in (301, 302)
    assert f'/forum/thread/{tid}' in r.headers.get('Location', '')

    rows = _replies(tid)
    assert len(rows) == 1
    assert rows[0]['content'] == '回复正文 **粗体**'
    assert rows[0]['user_id'] == admin['id']

    # 重新看帖：回复内容经 Markdown 渲染（**粗体** → <strong>）
    r2 = client.get(f'/forum/thread/{tid}')
    assert r2.status_code == 200
    assert b'<strong>' in r2.data


def test_view_thread_post_empty_reply_rejected(client, admin_login):
    admin = db.get_user_by_username(admin_login)
    tid = _make_thread(user_id=admin['id'])
    r = client.post(f'/forum/thread/{tid}',
                    data={'content': '   '},
                    follow_redirects=True)
    assert r.status_code == 200
    assert '回复内容不能为空'.encode() in r.data
    assert _count('forum_replies') == 0


def test_reply_thread_endpoint_persists(client, admin_login):
    admin = db.get_user_by_username(admin_login)
    tid = _make_thread(user_id=admin['id'])
    r = client.post(f'/forum/reply/{tid}',
                    data={'content': '通过 reply_thread 端点回复'})
    assert r.status_code in (301, 302)
    assert f'/forum/thread/{tid}' in r.headers.get('Location', '')

    rows = _replies(tid)
    assert len(rows) == 1
    assert rows[0]['content'] == '通过 reply_thread 端点回复'
    assert rows[0]['user_id'] == admin['id']
