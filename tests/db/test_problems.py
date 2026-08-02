# -*- coding: utf-8 -*-
"""DB 层测试：题目 CRUD、LLM 端点软绑定与 ensure_*_column 幂等。

被测函数（oj_modules/db_services.py）：
- create_problem  : type1 → max_score=0；type2 → max_score=5；输出文件名/端点绑定归一化；commit。
- get_problem     : 返回整行（含 content/initial_code/test_code/forbidden_func/submission_limit
                    及运行所需 grading 列和端点绑定）；不存在→None。
- get_all_problems: 按 id 升序；省略 content/initial_code/test_code/forbidden_func/submission_limit 等大字段。
- update_problem  : 普通字段直接写入；mode/filename 归一化，端点绑定按显式输入替换。
- ensure_problem_*_column / ensure_problem_grading_columns: 借助模块级 _*_ready 标志做幂等，连调两次不报错。
"""
from oj_modules import db_services as db
from tests import helpers as h


def _get_problem_by_title(title):
    """直接 SQL 取最新一条同名题目，返回整行 dict。"""
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM problems WHERE title=%s ORDER BY id DESC LIMIT 1",
                (title,),
            )
            return cur.fetchone()
    finally:
        conn.close()


# --------------------------------------------------------------------------
# create_problem
# --------------------------------------------------------------------------
def test_create_problem_type1_max_score_zero():
    db.create_problem(title='编程题A', content='题面', type=1, lang='python')
    row = _get_problem_by_title('编程题A')
    assert row is not None
    assert row['type'] == 1
    assert row['max_score'] == 0


def test_create_problem_type2_max_score_five():
    db.create_problem(title='书面题B', content='题面', type=2, lang='matlab')
    row = _get_problem_by_title('书面题B')
    assert row is not None
    assert row['type'] == 2
    assert row['max_score'] == 5


def test_create_problem_normalizes_programming_fields():
    db.create_problem(
        title='编程题归一化',
        content='c',
        type=1,
        lang='c',
        programming_grading_mode=99,                 # 越界 → 1
        programming_output_filename='dir\\sub\\out.PNG',  # 取最后一段
    )
    row = _get_problem_by_title('编程题归一化')
    assert row['programming_grading_mode'] == 1
    assert row['programming_grading_model'] == ''
    fn = row['programming_output_filename']
    assert fn.endswith('out.PNG')
    assert '\\' not in fn and '/' not in fn


def test_create_problem_normalizes_written_fields():
    db.create_problem(
        title='书面题归一化',
        content='w',
        type=2,
        lang='matlab',
        written_grading_mode=77,                  # 越界 → 1
    )
    row = _get_problem_by_title('书面题归一化')
    assert row['written_grading_mode'] == 1
    assert row['written_grading_model'] == ''


def test_create_problem_persists_written_llm_endpoint_bindings_as_json():
    bindings = {
        'ocr_endpoint_id': 101,
        'text_grading_endpoint_id': 102,
        'direct_image_grading_endpoint_id': 103,
    }
    pid = db.create_problem(
        title='书面题端点绑定',
        content='w',
        type=2,
        lang='matlab',
        llm_endpoint_bindings=bindings,
    )

    assert db.get_problem(pid)['llm_endpoint_bindings'] == bindings
    raw = _get_problem_by_title('书面题端点绑定')
    assert raw['llm_endpoint_bindings'] is not None


# --------------------------------------------------------------------------
# get_problem
# --------------------------------------------------------------------------
def test_get_problem_returns_full_row():
    pid = h.make_problem(
        title='全列题',
        content='完整题面',
        lang='python',
        type=1,
        time_limit_ms=3000,
        submission_limit=7,
        test_code='assert True',
        forbidden_func='sin',
        initial_code='print(0)',
    )
    row = db.get_problem(pid)
    assert row is not None
    # 大字段必须存在于 get_problem 返回里。
    for col in (
        'id', 'title', 'content', 'initial_code', 'test_code', 'forbidden_func',
        'type', 'lang', 'max_score', 'time_limit_ms', 'submission_limit',
        'written_grading_mode', 'written_grading_prompt',
        'programming_grading_mode',
        'programming_output_filename', 'programming_grading_prompt',
        'llm_endpoint_bindings',
    ):
        assert col in row, f"缺少列: {col}"
    assert 'written_grading_model' not in row
    assert 'programming_grading_model' not in row
    assert row['id'] == pid
    assert row['title'] == '全列题'
    assert row['content'] == '完整题面'
    assert row['initial_code'] == 'print(0)'
    assert row['test_code'] == 'assert True'
    assert row['forbidden_func'] == 'sin'
    assert row['time_limit_ms'] == 3000
    assert row['submission_limit'] == 7


def test_get_problem_missing_returns_none():
    assert db.get_problem(999999) is None


# --------------------------------------------------------------------------
# get_all_problems
# --------------------------------------------------------------------------
def test_get_all_problems_id_ascending_and_omits_big_fields():
    p1 = h.make_problem(title='列表题1', type=1, lang='python')
    p2 = h.make_problem(title='列表题2', type=2, lang='matlab')
    p3 = h.make_problem(title='列表题3', type=1, lang='c')

    rows = db.get_all_problems()
    ids = [r['id'] for r in rows]
    assert ids == sorted(ids)            # id 升序
    assert {p1, p2, p3}.issubset(set(ids))

    sample = rows[0]
    # 省略的大字段不应出现在列表查询里。
    for omitted in ('content', 'initial_code', 'test_code', 'forbidden_func', 'submission_limit'):
        assert omitted not in sample, f"列表不应包含大字段: {omitted}"
    # 列表保留的精简字段。
    for kept in ('id', 'title', 'cnt', 'type', 'lang', 'max_score', 'time_limit_ms'):
        assert kept in sample, f"列表缺少字段: {kept}"


# --------------------------------------------------------------------------
# update_problem
# --------------------------------------------------------------------------
def test_update_problem_writes_basic_fields():
    pid = h.make_problem(title='待改题', content='旧', lang='python', type=1)
    db.update_problem(
        pid,
        new_title='已改标题',
        new_content='新内容',
        new_initial_code='print(1)',
        new_test_code='check',
        new_forbidden_func='printf',
        new_lang='c',
        new_time_limit_ms=5000,
        new_submission_limit=3,
    )
    row = db.get_problem(pid)
    assert row['title'] == '已改标题'
    assert row['content'] == '新内容'
    assert row['initial_code'] == 'print(1)'
    assert row['test_code'] == 'check'
    assert row['forbidden_func'] == 'printf'
    assert row['lang'] == 'c'
    assert row['time_limit_ms'] == 5000
    assert row['submission_limit'] == 3


def test_update_problem_none_grading_fields_use_defaults():
    pid = h.make_problem(title='默认归一化题', lang='python', type=1)
    # 所有 grading 相关参数留 None → 落库为默认值。
    db.update_problem(pid, new_title='默认归一化题', new_content='c', new_lang='python')
    row = db.get_problem(pid)
    assert row['programming_grading_mode'] == 1
    assert row['programming_output_filename'] == 'output.png'
    assert row['programming_grading_prompt'] == ''
    assert row['written_grading_mode'] == 1
    assert row['written_grading_prompt'] == ''
    assert 'programming_grading_model' not in row
    assert 'written_grading_model' not in row


def test_update_problem_non_none_grading_fields_take_effect():
    pid = h.make_problem(title='生效归一化题', lang='c', type=1)
    db.update_problem(
        pid,
        new_title='生效归一化题',
        new_content='c',
        new_lang='c',
        new_programming_grading_mode=2,
        new_programming_output_filename='res\\final.png',
        new_programming_grading_prompt='  请评分  ',
    )
    row = db.get_problem(pid)
    assert row['programming_grading_mode'] == 2
    assert row['programming_output_filename'] == 'final.png'
    assert row['programming_grading_prompt'] == '请评分'   # 被 strip
    assert _get_problem_by_title('生效归一化题')['programming_grading_model'] == ''


def test_update_problem_replaces_bindings_without_rewriting_legacy_model_string():
    pid = db.create_problem(
        title='Promptly端点绑定',
        content='c',
        type=1,
        lang='python',
        programming_grading_mode=3,
    )
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE problems SET programming_grading_model=%s WHERE id=%s",
                ('legacy-custom-model', pid),
            )
        conn.commit()
    finally:
        conn.close()

    db.update_problem(
        pid,
        new_title='Promptly端点绑定',
        new_content='c2',
        new_lang='python',
        new_llm_endpoint_bindings={
            'review_endpoint_id': 201,
            'code_generation_endpoint_id': 202,
        },
    )

    row = db.get_problem(pid)
    assert _get_problem_by_title('Promptly端点绑定')['programming_grading_model'] == 'legacy-custom-model'
    assert row['llm_endpoint_bindings'] == {
        'review_endpoint_id': 201,
        'code_generation_endpoint_id': 202,
    }


# --------------------------------------------------------------------------
# ensure_problem_*_column 幂等（连调两次不报错；与 grading 聚合函数一致）
# --------------------------------------------------------------------------
def test_ensure_column_functions_idempotent():
    fns = (
        db.ensure_problem_written_grading_mode_column,
        db.ensure_problem_written_grading_model_column,
        db.ensure_problem_written_grading_prompt_column,
        db.ensure_problem_programming_grading_mode_column,
        db.ensure_problem_programming_grading_model_column,
        db.ensure_problem_programming_output_filename_column,
        db.ensure_problem_programming_grading_prompt_column,
        db.ensure_problem_written_grading_columns,
        db.ensure_problem_programming_grading_columns,
        db.ensure_problem_grading_columns,
    )
    # 连调两次：第二次走 _*_ready 短路；任一调用都不应抛异常。
    for fn in fns:
        fn()
        fn()


def test_ensure_grading_columns_present_after_call():
    db.ensure_problem_grading_columns()
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM problems")
            cols = {r['Field'] for r in cur.fetchall()}
    finally:
        conn.close()
    for col in (
        'written_grading_mode', 'written_grading_model', 'written_grading_prompt',
        'programming_grading_mode', 'programming_grading_model',
        'programming_output_filename', 'programming_grading_prompt',
    ):
        assert col in cols, f"ensure 后仍缺列: {col}"


def test_problem_test_code_column_is_longtext():
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM problems LIKE 'test_code'")
            col = cur.fetchone()
    finally:
        conn.close()

    assert col is not None
    assert str(col['Type']).lower() == 'longtext'
