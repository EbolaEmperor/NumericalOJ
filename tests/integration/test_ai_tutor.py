# -*- coding: utf-8 -*-
"""ai_routes.py 集成测试（§4k + §3a/§3d）：AI 助教 / 代码标注。

源码事实（oj_modules/routes/ai_routes.py）：
- `ask_ai_code_marks` POST `/ask_ai_code_marks` —— JSON 体 `problem_id,user_code,
  submission_id,force_refresh`。校验顺序：缺请求体(400)→题目存在(404)→题目内容(400)→
  用户代码(400)→提交存在(404)→登录(401)→owner/admin(403)。未强制刷新且命中缓存
  返回 `source='cache'`；否则调用 `generate_ai_code_marks_from_submission_context(
  ...,max_issues=8,timeout=240)` 并写缓存后返回 `source='generated'`。异常 → 500。
- `ask_ai` POST `/ask_ai` —— JSON `problem_id,user_code,submission_id`；校验顺序：
  缺请求体(400)→（读 problem/submission，访问 submission["test_points"]）→题目内容(400)
  →用户代码(400)→登录(401)；成功返回 `generate_completion_stream(prompt)` 的 text/plain 流。
- `ask_ai_for_ac` POST `/ask_ai_for_ac` —— JSON `problem_id,user_code`；校验顺序：
  缺请求体(400)→题目内容(400)→用户代码(400)→登录(401)；成功返回 text/plain 流。
- `generate_completion_stream(prompt, model='Qwen3')` 是生成器；route 内 `generate_answer()`
  逐块 yield，异常被吞为 `[服务端异常] ...`。

约定：DB 每个用例前 truncate+reseed（admin / Cclass1 等）；AI/SMTP 自动 mock。
本文件按需用 monkeypatch 覆盖 ai_routes / ai_utils 的具体接缝以断言确定输出。
"""
import json

from oj_modules import db_services as db
from oj_modules.routes import ai_routes
from tests import helpers


# --------------------------- 公共构造 ---------------------------

def _setup_problem_submission(owner_username, content='求两数之和', lang='python',
                              code='print(1+2)', test_points=None):
    """建一道题 + 一个属于 owner 的提交，返回 (problem_id, submission_id)。"""
    pid = helpers.make_problem(content=content, lang=lang)
    sid = helpers.make_submission(
        pid, owner_username, code=code,
        test_points=test_points if test_points is not None else [
            {"name": "test1", "status": "Wrong Answer", "score": 0},
        ],
    )
    return pid, sid


def _get_submission_row(sid):
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM submissions WHERE id=%s", (sid,))
            return cur.fetchone()
    finally:
        conn.close()


# =========================== ask_ai_code_marks ===========================

def test_ask_ai_code_marks_owner_generated(client, login, monkeypatch):
    """owner 登录 + mock 生成器 → success:true + 固定 issues/summary + source='generated'，并落库缓存。"""
    owner = helpers.make_user(username='alice')
    pid, sid = _setup_problem_submission('alice')
    login('alice')

    fixed = {
        "issues": [{"line_start": 1, "line_end": 1, "reason": "下标越界", "severity": "high"}],
        "summary": "存在一个数组越界问题",
        "code_used": "print(1+2)",
        "image_mismatch_analysis": "",
        "image_analysis_test_index": None,
    }
    monkeypatch.setattr(
        ai_routes, 'generate_ai_code_marks_from_submission_context',
        lambda *a, **k: fixed,
    )

    r = client.post('/ask_ai_code_marks', json={
        'problem_id': pid, 'user_code': 'print(1+2)', 'submission_id': sid,
    })
    assert r.status_code == 200
    data = r.get_json()
    assert data['success'] is True
    assert data['source'] == 'generated'
    assert data['summary'] == '存在一个数组越界问题'
    assert data['issues'] == fixed['issues']

    # 写库缓存：ai_code_marks_json 应被填充，且 summary 一致
    row = _get_submission_row(sid)
    assert row['ai_code_marks_json']
    cached = json.loads(row['ai_code_marks_json'])
    assert cached['summary'] == '存在一个数组越界问题'


def test_ask_ai_code_marks_max_issues_and_timeout_passed(client, login, monkeypatch):
    """断言 route 以 max_issues=8, timeout=240 调用生成函数。"""
    helpers.make_user(username='alice')
    pid, sid = _setup_problem_submission('alice')
    login('alice')

    captured = {}

    def _fake(*a, **k):
        captured.update(k)
        return {"issues": [], "summary": "ok"}

    monkeypatch.setattr(ai_routes, 'generate_ai_code_marks_from_submission_context', _fake)
    r = client.post('/ask_ai_code_marks', json={
        'problem_id': pid, 'user_code': 'print(1)', 'submission_id': sid,
    })
    assert r.status_code == 200
    assert captured.get('max_issues') == 8
    assert captured.get('timeout') == 240


def test_ask_ai_code_marks_admin_can_access_others(client, admin_login, monkeypatch):
    """admin 可访问他人提交（owner 是 alice，admin 登录）→ 200 generated。"""
    helpers.make_user(username='alice')
    pid, sid = _setup_problem_submission('alice')
    # admin_login 已登录 admin

    monkeypatch.setattr(
        ai_routes, 'generate_ai_code_marks_from_submission_context',
        lambda *a, **k: {"issues": [], "summary": "admin 视角"},
    )
    r = client.post('/ask_ai_code_marks', json={
        'problem_id': pid, 'user_code': 'print(1)', 'submission_id': sid,
    })
    assert r.status_code == 200
    assert r.get_json()['success'] is True


def test_ask_ai_code_marks_other_user_forbidden(client, login, monkeypatch):
    """非 owner 非 admin → 403 无权访问该提交。"""
    helpers.make_user(username='alice')
    helpers.make_user(username='bob')
    pid, sid = _setup_problem_submission('alice')
    login('bob')

    # 即便 mock 了生成器也不应被调用
    monkeypatch.setattr(
        ai_routes, 'generate_ai_code_marks_from_submission_context',
        lambda *a, **k: {"issues": [], "summary": "不该被调用"},
    )
    r = client.post('/ask_ai_code_marks', json={
        'problem_id': pid, 'user_code': 'print(1)', 'submission_id': sid,
    })
    assert r.status_code == 403
    data = r.get_json()
    assert data['success'] is False
    assert data['message'] == '无权访问该提交'


def test_ask_ai_code_marks_cache_hit_returns_source_cache(client, login, monkeypatch):
    """提交已带 ai_code_marks_json 缓存且未 force_refresh → source='cache'，不调用生成函数。"""
    helpers.make_user(username='alice')
    pid, sid = _setup_problem_submission('alice', code='print(99)')
    login('alice')

    payload = {
        "issues": [{"line_start": 1, "line_end": 1, "reason": "缓存命中原因", "severity": "low"}],
        "summary": "这是缓存里的总结",
        "code_used": "print(99)",
        "image_mismatch_analysis": "",
        "image_analysis_test_index": None,
        "generated_at": "2026-05-29T00:00:00Z",
        "model": "test-model",
    }
    db.save_submission_ai_code_marks_json(sid, payload)

    def _should_not_call(*a, **k):
        raise AssertionError("命中缓存时不应调用生成函数")

    monkeypatch.setattr(ai_routes, 'generate_ai_code_marks_from_submission_context', _should_not_call)

    r = client.post('/ask_ai_code_marks', json={
        'problem_id': pid, 'user_code': 'print(99)', 'submission_id': sid,
    })
    assert r.status_code == 200
    data = r.get_json()
    assert data['source'] == 'cache'
    assert data['success'] is True
    assert data['summary'] == '这是缓存里的总结'


def test_ask_ai_code_marks_force_refresh_bypasses_cache(client, login, monkeypatch):
    """force_refresh=True → 即便有缓存也重新生成，source='generated'。"""
    helpers.make_user(username='alice')
    pid, sid = _setup_problem_submission('alice', code='print(7)')
    login('alice')

    db.save_submission_ai_code_marks_json(sid, {
        "issues": [], "summary": "旧缓存", "code_used": "print(7)",
        "generated_at": "2026-05-29T00:00:00Z",
    })
    monkeypatch.setattr(
        ai_routes, 'generate_ai_code_marks_from_submission_context',
        lambda *a, **k: {"issues": [], "summary": "新生成"},
    )
    r = client.post('/ask_ai_code_marks', json={
        'problem_id': pid, 'user_code': 'print(7)', 'submission_id': sid,
        'force_refresh': True,
    })
    assert r.status_code == 200
    data = r.get_json()
    assert data['source'] == 'generated'
    assert data['summary'] == '新生成'


def test_ask_ai_code_marks_not_logged_in_401(client):
    """未登录 → 401（题目/代码/提交均存在，确保能走到登录检查）。"""
    helpers.make_user(username='alice')
    pid, sid = _setup_problem_submission('alice')
    r = client.post('/ask_ai_code_marks', json={
        'problem_id': pid, 'user_code': 'print(1)', 'submission_id': sid,
    })
    assert r.status_code == 401
    data = r.get_json()
    assert data['success'] is False
    assert data['message'] == '未登录'


def test_ask_ai_code_marks_problem_not_found_404(client, login):
    """题目不存在 → 404。"""
    helpers.make_user(username='alice')
    login('alice')
    r = client.post('/ask_ai_code_marks', json={
        'problem_id': 999999, 'user_code': 'print(1)', 'submission_id': 1,
    })
    assert r.status_code == 404
    assert r.get_json()['message'] == '题目不存在'


def test_ask_ai_code_marks_missing_user_code_400(client, login):
    """缺用户代码 → 400。"""
    helpers.make_user(username='alice')
    pid, sid = _setup_problem_submission('alice')
    login('alice')
    r = client.post('/ask_ai_code_marks', json={
        'problem_id': pid, 'user_code': '   ', 'submission_id': sid,
    })
    assert r.status_code == 400
    assert r.get_json()['message'] == '缺少用户代码'


def test_ask_ai_code_marks_submission_not_found_404(client, login):
    """提交不存在 → 404。"""
    helpers.make_user(username='alice')
    pid, _ = _setup_problem_submission('alice')
    login('alice')
    r = client.post('/ask_ai_code_marks', json={
        'problem_id': pid, 'user_code': 'print(1)', 'submission_id': 888888,
    })
    assert r.status_code == 404
    assert r.get_json()['message'] == '提交记录不存在'


def test_ask_ai_code_marks_generation_error_500(client, login, monkeypatch):
    """生成函数抛异常 → 500，message 含失败前缀。"""
    helpers.make_user(username='alice')
    pid, sid = _setup_problem_submission('alice')
    login('alice')

    def _boom(*a, **k):
        raise RuntimeError("模型炸了")

    monkeypatch.setattr(ai_routes, 'generate_ai_code_marks_from_submission_context', _boom)
    r = client.post('/ask_ai_code_marks', json={
        'problem_id': pid, 'user_code': 'print(1)', 'submission_id': sid,
    })
    assert r.status_code == 500
    data = r.get_json()
    assert data['success'] is False
    assert '标注生成失败' in data['message']


# =============================== ask_ai ===============================

def test_ask_ai_streams_text(client, login, monkeypatch):
    """登录 + mock generate_completion_stream 为产出几段文本的生成器 → text/plain 含全部内容。"""
    helpers.make_user(username='alice')
    pid, sid = _setup_problem_submission('alice')
    login('alice')

    def _fake_stream(prompt, model="Qwen3"):
        yield "喵～"
        yield "你的第 1 个测试点"
        yield "建议检查边界"

    monkeypatch.setattr(ai_routes, 'generate_completion_stream', _fake_stream)
    r = client.post('/ask_ai', json={
        'problem_id': pid, 'user_code': 'print(1)', 'submission_id': sid,
    })
    assert r.status_code == 200
    assert r.mimetype == 'text/plain'
    text = r.get_data(as_text=True)
    assert '喵～' in text
    assert '你的第 1 个测试点' in text
    assert '建议检查边界' in text


def test_ask_ai_stream_swallows_exception(client, login, monkeypatch):
    """生成器中途抛异常 → 被吞为 [服务端异常] 文案，仍 200。"""
    helpers.make_user(username='alice')
    pid, sid = _setup_problem_submission('alice')
    login('alice')

    def _broken_stream(prompt, model="Qwen3"):
        yield "开头正常"
        raise RuntimeError("中途崩了")

    monkeypatch.setattr(ai_routes, 'generate_completion_stream', _broken_stream)
    r = client.post('/ask_ai', json={
        'problem_id': pid, 'user_code': 'print(1)', 'submission_id': sid,
    })
    assert r.status_code == 200
    text = r.get_data(as_text=True)
    assert '开头正常' in text
    assert '[服务端异常]' in text


def test_ask_ai_not_logged_in_401(client, monkeypatch):
    """ask_ai 未登录 → 401（题目/代码/提交均存在，确保走到登录检查）。"""
    helpers.make_user(username='alice')
    pid, sid = _setup_problem_submission('alice')

    # 不应调用流式生成
    monkeypatch.setattr(
        ai_routes, 'generate_completion_stream',
        lambda *a, **k: (_ for _ in ()),
    )
    r = client.post('/ask_ai', json={
        'problem_id': pid, 'user_code': 'print(1)', 'submission_id': sid,
    })
    assert r.status_code == 401
    assert r.get_json()['message'] == '未登录'


# ============================ ask_ai_for_ac ============================

def test_ask_ai_for_ac_streams_text(client, login, monkeypatch):
    """ask_ai_for_ac 登录 + mock 流 → text/plain 含全部内容（无需 submission_id）。"""
    helpers.make_user(username='alice')
    pid = helpers.make_problem(content='恭喜通过', lang='cpp')
    login('alice')

    def _fake_stream(prompt, model="Qwen3"):
        yield "🎉 恭喜你 AC！"
        yield "你的代码结构清晰"

    monkeypatch.setattr(ai_routes, 'generate_completion_stream', _fake_stream)
    r = client.post('/ask_ai_for_ac', json={
        'problem_id': pid, 'user_code': 'int main(){return 0;}',
    })
    assert r.status_code == 200
    assert r.mimetype == 'text/plain'
    text = r.get_data(as_text=True)
    assert '恭喜你 AC' in text
    assert '你的代码结构清晰' in text


def test_ask_ai_for_ac_missing_user_code_400(client, login):
    """ask_ai_for_ac 缺用户代码 → 400。"""
    helpers.make_user(username='alice')
    pid = helpers.make_problem(content='恭喜通过', lang='matlab')
    login('alice')
    r = client.post('/ask_ai_for_ac', json={
        'problem_id': pid, 'user_code': '   ',
    })
    assert r.status_code == 400
    assert r.get_json()['message'] == '缺少用户代码'


def test_ask_ai_for_ac_not_logged_in_401(client, monkeypatch):
    """ask_ai_for_ac 未登录 → 401。"""
    helpers.make_user(username='alice')
    pid = helpers.make_problem(content='恭喜通过', lang='matlab')

    monkeypatch.setattr(
        ai_routes, 'generate_completion_stream',
        lambda *a, **k: (_ for _ in ()),
    )
    r = client.post('/ask_ai_for_ac', json={
        'problem_id': pid, 'user_code': 'disp(1)',
    })
    assert r.status_code == 401
    assert r.get_json()['message'] == '未登录'
