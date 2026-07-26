# -*- coding: utf-8 -*-
"""DB 层测试：users / 班级 / site_settings（参考计划 Task 19 + 契约 §1a）。

被测函数（oj_modules/db_services.py）：
- create_user：插 users + class_table.class_cnt+1 + user_class_map
- get_user_by_username / get_user_by_id / get_user_by_email
- get_user_classes：只读 user_class_map，按 class_en ASC 稳定排序
- get_all_classes / get_class_by_en / get_class_by_cn
- get_setting / set_setting：site_settings 往返
- is_class_adjust_enabled：默认 True；set '0' → False

DB 由 conftest 的 autouse db_reset 在每个测试前 truncate+reseed
（种子：admin 用户、Cclass1 班级、site_settings class_adjust_enabled='1'）。
"""
from oj_modules import db_services as db
from tests import helpers as h


# ---------------------------------------------------------------------------
# create_user：链接班级 + class_cnt 自增
# ---------------------------------------------------------------------------
def test_create_user_keeps_class_membership_out_of_users_row():
    h.make_class('Cx', '班X')
    db.create_user('alice', h.sha256_hex('pw'), 'alice@e.com',
                   {'class_en': 'Cx', 'class_cn': '班X'})
    u = db.get_user_by_username('alice')
    assert u is not None
    assert u['username'] == 'alice'
    assert 'class' not in u
    assert 'class_cn' not in u
    assert u['email'] == 'alice@e.com'
    # 密码按调用方传入的 hash 原样存储（无二次加密）
    assert u['password_hash'] == h.sha256_hex('pw')


def test_create_user_adds_equal_membership():
    h.make_class('Cx', '班X')
    db.create_user('bob', h.sha256_hex('pw'), 'bob@e.com',
                   {'class_en': 'Cx', 'class_cn': '班X'})
    u = db.get_user_by_username('bob')
    cls = db.get_user_classes(u['id'])
    assert cls == [{
        'class_en': 'Cx',
        'class_cn': '班X',
        'logo_seed': None,
    }]


def test_create_user_increments_class_cnt():
    h.make_class('Cx', '班X')
    before = db.get_class_by_en('Cx')  # class_cnt 不在该 getter 返回里，单独查
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT class_cnt FROM class_table WHERE class_en=%s", ('Cx',))
            cnt_before = cur.fetchone()['class_cnt']
    finally:
        conn.close()
    assert before is not None

    db.create_user('carol', h.sha256_hex('pw'), 'carol@e.com',
                   {'class_en': 'Cx', 'class_cn': '班X'})

    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT class_cnt FROM class_table WHERE class_en=%s", ('Cx',))
            cnt_after = cur.fetchone()['class_cnt']
    finally:
        conn.close()
    assert cnt_after == cnt_before + 1


# ---------------------------------------------------------------------------
# get_user_by_username / _by_id / _by_email
# ---------------------------------------------------------------------------
def test_get_user_lookup_variants_agree():
    u = h.make_user('lookupuser', email='lookup@e.com')
    by_name = db.get_user_by_username('lookupuser')
    by_id = db.get_user_by_id(u['id'])
    by_email = db.get_user_by_email('lookup@e.com')
    assert by_name['id'] == u['id']
    assert by_id['username'] == 'lookupuser'
    assert by_email['id'] == u['id']


def test_get_user_lookup_missing_returns_none():
    assert db.get_user_by_username('does-not-exist') is None
    assert db.get_user_by_id(99999999) is None
    assert db.get_user_by_email('nobody@nowhere.invalid') is None


# ---------------------------------------------------------------------------
# get_user_classes：映射表唯一事实源 + 稳定排序
# ---------------------------------------------------------------------------
def test_get_user_classes_orders_by_class_en():
    u = h.make_user('multi', class_en='Cz', class_cn='末班')
    h.make_class('Ca', '首班')
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO user_class_map (user_id, class_en) "
                "VALUES (%s, %s)", (u['id'], 'Ca'))
        conn.commit()
    finally:
        conn.close()

    cls = db.get_user_classes(u['id'])
    assert len(cls) == 2
    assert [item['class_en'] for item in cls] == ['Ca', 'Cz']
    assert [item['class_cn'] for item in cls] == ['首班', '末班']
    assert all('is_primary' not in item for item in cls)


def test_get_user_classes_admin_without_membership_returns_empty():
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users "
                "(username, password_hash, is_admin, email) "
                "VALUES (%s, %s, 1, %s)",
                ('teacher', h.sha256_hex('pw'), 'teacher@e.com'),
            )
        conn.commit()
    finally:
        conn.close()

    u = db.get_user_by_username('teacher')
    assert db.get_user_classes(u['id']) == []


def test_get_users_in_classes_aggregates_all_matching_classes():
    u = h.make_user('aggregate', class_en='Cb', class_cn='乙班')
    h.make_class('Ca', '甲班')
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO user_class_map (user_id, class_en) "
                "VALUES (%s, %s)",
                (u['id'], 'Ca'),
            )
        conn.commit()
    finally:
        conn.close()

    users = db.get_users_in_classes(['Cb', 'Ca'])

    assert users == [{
        'user_id': u['id'],
        'username': 'aggregate',
        'classes': [
            {'class_en': 'Ca', 'class_cn': '甲班'},
            {'class_en': 'Cb', 'class_cn': '乙班'},
        ],
        'classes_display': '甲班 / 乙班',
    }]
    assert 'class_cn' not in users[0]


# ---------------------------------------------------------------------------
# get_all_classes / get_class_by_en / get_class_by_cn
# ---------------------------------------------------------------------------
def test_get_all_classes_includes_seeded():
    rows = db.get_all_classes()
    ens = {r['class_en'] for r in rows}
    assert 'Cclass1' in ens
    assert 'Cadmin' not in ens


def test_get_class_by_en_and_cn():
    by_en = db.get_class_by_en('Cclass1')
    assert by_en is not None
    assert by_en['class_en'] == 'Cclass1'
    assert by_en['class_cn'] == '测试班级'

    by_cn = db.get_class_by_cn('测试班级')
    assert by_cn is not None
    assert by_cn['class_en'] == 'Cclass1'


def test_get_class_by_en_missing_returns_none():
    assert db.get_class_by_en('CnoSuchClass') is None
    assert db.get_class_by_cn('不存在的班级名') is None


# ---------------------------------------------------------------------------
# get_setting / set_setting：site_settings 往返
# ---------------------------------------------------------------------------
def test_get_setting_default_when_absent():
    assert db.get_setting('no_such_key') is None
    assert db.get_setting('no_such_key', default='fallback') == 'fallback'


def test_set_setting_roundtrip():
    db.set_setting('my_key', 'my_value')
    assert db.get_setting('my_key') == 'my_value'


def test_set_setting_overwrites_existing():
    db.set_setting('dup_key', 'first')
    db.set_setting('dup_key', 'second')
    assert db.get_setting('dup_key') == 'second'


def test_set_setting_stringifies_value():
    # set_setting 内部 str(value)，故整数往返回字符串
    db.set_setting('int_key', 123)
    assert db.get_setting('int_key') == '123'


# ---------------------------------------------------------------------------
# is_class_adjust_enabled：默认 True；'0' → False
# ---------------------------------------------------------------------------
def test_is_class_adjust_enabled_default_true():
    # 种子里 class_adjust_enabled='1'
    assert db.is_class_adjust_enabled() is True


def test_is_class_adjust_enabled_toggle():
    db.set_setting('class_adjust_enabled', '0')
    assert db.is_class_adjust_enabled() is False
    db.set_setting('class_adjust_enabled', '1')
    assert db.is_class_adjust_enabled() is True
