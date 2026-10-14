"""AI Vote 复制候选的权限、完整兼容性与只读边界。"""

from copy import deepcopy

import pytest
from flask import Flask

from backend.oj_modules.api import problem_api
from backend.oj_modules.problems import written_vote_copy
from backend.oj_modules.problems.llm_bindings import (
    DIRECT_IMAGE_GRADING_ENDPOINT_ID,
    TEXT_GRADING_ENDPOINT_ID,
    build_problem_llm_endpoint_candidates,
)


def written_problem(problem_id, *, mode=1, votes=None, bindings=None, **extra):
    return {
        "id": problem_id,
        "title": f"书面题 {problem_id}",
        "type": 2,
        "written_grading_mode": mode,
        "written_vote_config": votes or [],
        "llm_endpoint_bindings": bindings or {},
        **extra,
    }


@pytest.fixture
def client(monkeypatch):
    app = Flask(__name__)
    app.config.update(TESTING=True)
    app.register_blueprint(problem_api.problem_api_bp)
    monkeypatch.setattr(problem_api, "current_user", lambda: {"is_admin": 1})
    monkeypatch.setattr(problem_api, "list_written_vote_copy_sources", lambda: [])
    candidates = build_problem_llm_endpoint_candidates([
        {"id": 1, "category": "text", "model": "text", "api_key": "不能返回"},
        {"id": 2, "category": "vision", "model": "vision"},
        {"id": 3, "category": "omni", "model": "omni"},
    ])
    monkeypatch.setattr(problem_api, "_problem_llm_endpoint_candidates", lambda: candidates)
    return app.test_client()


@pytest.mark.parametrize("user", [None, {"is_admin": 0}, {"is_admin": "1"}])
def test_only_authenticated_admin_can_read_configs(client, monkeypatch, user):
    monkeypatch.setattr(problem_api, "current_user", lambda: user)
    monkeypatch.setattr(
        problem_api, "list_written_vote_copy_sources", lambda: pytest.fail("鉴权失败不应读题目"),
    )
    monkeypatch.setattr(
        problem_api, "_problem_llm_endpoint_candidates",
        lambda: pytest.fail("鉴权失败不应读端点"),
    )
    response = client.get("/api/admin/problems/written-vote-configs?is_admin=1")
    assert response.status_code == 403


@pytest.mark.parametrize("query", [
    "grading_mode=", "grading_mode=0", "grading_mode=4", "grading_mode=text",
    "grading_mode=1.0", "exclude_problem_id=", "exclude_problem_id=0",
    "exclude_problem_id=-1", "exclude_problem_id=1.0", "exclude_problem_id=abc",
    "exclude_problem_id=9223372036854775808",
])
def test_invalid_copy_parameters_fail_before_reading(client, monkeypatch, query):
    monkeypatch.setattr(
        problem_api, "list_written_vote_copy_sources", lambda: pytest.fail("无效参数不应读题目"),
    )
    monkeypatch.setattr(
        problem_api, "_problem_llm_endpoint_candidates",
        lambda: pytest.fail("无效参数不应读端点"),
    )
    assert client.get(f"/api/admin/problems/written-vote-configs?{query}").status_code == 400


@pytest.mark.parametrize("mode,expected_ids", [
    (1, [11, 13, 17]), (2, [12, 13, 17]), (3, [11, 13, 17]),
])
def test_copy_filters_complete_configs_by_target_mode(client, monkeypatch, mode, expected_ids):
    problems = [
        written_problem(11, votes=[{"endpoint_id": 1, "count": 2}]),
        written_problem(12, mode=2, votes=[{"endpoint_id": 2, "count": 1}]),
        written_problem(13, mode=2, votes=[{"endpoint_id": 3, "count": 3}]),
        written_problem(14, votes=[{"endpoint_id": 1, "count": 1}, {"endpoint_id": 2, "count": 2}]),
        written_problem(15, votes=[{"endpoint_id": 99, "count": 1}]),
        written_problem(16, mode=4),
        written_problem(17),
        written_problem(18, type=1),
        written_problem(19, mode=0),
    ]
    monkeypatch.setattr(problem_api, "list_written_vote_copy_sources", lambda: problems)
    response = client.get(f"/api/admin/problems/written-vote-configs?grading_mode={mode}")
    assert response.status_code == 200
    items = response.json["problems"]
    assert [item["id"] for item in items] == expected_ids
    assert next(item for item in items if item["id"] == 13)["written_vote_config"] == [
        {"endpoint_id": 3, "count": 3},
    ]
    assert next(item for item in items if item["id"] == 17)["written_vote_config"] == []


def test_default_mode_excludes_current_problem_and_only_returns_copy_fields(client, monkeypatch):
    problems = [
        written_problem(11, votes=[{"endpoint_id": 1, "count": 2}], written_score_public=0,
                        written_grading_prompt="私有提示词", content="题面", api_key="不能返回"),
        written_problem(12, mode=3, votes=[{"endpoint_id": 3, "count": 1}]),
    ]
    original = deepcopy(problems)
    monkeypatch.setattr(problem_api, "list_written_vote_copy_sources", lambda: problems)
    response = client.get("/api/admin/problems/written-vote-configs?exclude_problem_id=12")
    assert response.status_code == 200
    assert response.json == {"success": True, "problems": [{
        "id": 11, "title": "书面题 11", "written_vote_config": [{"endpoint_id": 1, "count": 2}],
    }]}
    assert response.headers["Cache-Control"] == "no-store"
    assert problems == original
    assert client.post("/api/admin/problems/written-vote-configs").status_code == 405


@pytest.mark.parametrize("target_mode,expected", [
    (1, [(21, 1), (23, 3), (25, 1)]),
    (2, [(22, 2), (23, 3)]),
    (3, [(21, 1), (23, 3), (25, 1)]),
])
def test_legacy_binding_fallback_preserves_single_vote(client, monkeypatch, target_mode, expected):
    problems = [
        written_problem(21, bindings={TEXT_GRADING_ENDPOINT_ID: 1}),
        written_problem(22, mode=2, bindings={DIRECT_IMAGE_GRADING_ENDPOINT_ID: 2}),
        written_problem(23, mode=2, bindings={DIRECT_IMAGE_GRADING_ENDPOINT_ID: 3}),
        written_problem(24, bindings={TEXT_GRADING_ENDPOINT_ID: 99}),
        # 显式 Vote 优先于旧绑定，不能把旧绑定混入复制结果。
        written_problem(25, votes=[{"endpoint_id": 1, "count": 2}],
                        bindings={TEXT_GRADING_ENDPOINT_ID: 99}),
    ]
    monkeypatch.setattr(problem_api, "list_written_vote_copy_sources", lambda: problems)
    response = client.get(f"/api/admin/problems/written-vote-configs?grading_mode={target_mode}")
    assert response.status_code == 200
    assert [(item["id"], item["written_vote_config"][0]["endpoint_id"])
            for item in response.json["problems"]] == expected
    for item in response.json["problems"]:
        assert item["written_vote_config"][0]["count"] == (2 if item["id"] == 25 else 1)


def test_empty_config_does_not_copy_ocr_or_other_mode_binding(client, monkeypatch):
    monkeypatch.setattr(problem_api, "list_written_vote_copy_sources", lambda: [
        written_problem(30, bindings={"ocr_endpoint_id": 2, DIRECT_IMAGE_GRADING_ENDPOINT_ID: 2}),
    ])
    assert client.get("/api/admin/problems/written-vote-configs").json["problems"] == [{
        "id": 30, "title": "书面题 30", "written_vote_config": [],
    }]


def test_malformed_explicit_votes_are_not_partially_copied(client, monkeypatch):
    monkeypatch.setattr(problem_api, "list_written_vote_copy_sources", lambda: [
        written_problem(31, votes=[{"endpoint_id": 1, "count": 2}, {"endpoint_id": 1, "count": 1}]),
    ])
    assert client.get("/api/admin/problems/written-vote-configs").json["problems"] == []


@pytest.mark.parametrize("raw_config,bindings,expected", [
    ('[{"endpoint_id":1,"count":2}]', {}, [{"endpoint_id": 1, "count": 2}]),
    ("[{", {TEXT_GRADING_ENDPOINT_ID: 1}, None),
    ('[{"endpoint_id":1,"count":2},{"endpoint_id":1,"count":1}]',
     {TEXT_GRADING_ENDPOINT_ID: 1}, None),
    ('[{"endpoint_id":1,"count":6}]', {TEXT_GRADING_ENDPOINT_ID: 1}, None),
    ('[{"endpoint_id":1,"count":5},{"endpoint_id":3,"count":5},{"endpoint_id":9,"count":1}]',
     {TEXT_GRADING_ENDPOINT_ID: 1}, None),
    ("[]", {}, []),
    (None, {}, []),
    ("[]", '{"text_grading_endpoint_id":1}', [{"endpoint_id": 1, "count": 1}]),
])
def test_real_source_query_keeps_raw_config_and_only_selects(
    client, monkeypatch, raw_config, bindings, expected,
):
    statements = []
    row = written_problem(40, bindings=bindings)
    row["written_vote_config"] = raw_config
    original = deepcopy(row)
    # 三种端点均有效，超出总票数的来源只能因严格配置校验而被排除。
    monkeypatch.setattr(problem_api, "_problem_llm_endpoint_candidates", lambda: {
        TEXT_GRADING_ENDPOINT_ID: [{"id": endpoint_id} for endpoint_id in (1, 3, 9)],
    })

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def execute(self, sql):
            statements.append(sql)

        def fetchall(self):
            return [row]

    class Connection:
        closed = False

        def cursor(self):
            return Cursor()

        def close(self):
            self.closed = True

        def commit(self):
            pytest.fail("复制候选查询不得提交写操作")

    connection = Connection()
    monkeypatch.setattr(written_vote_copy, "get_db_connection", lambda: connection)
    monkeypatch.setattr(problem_api, "list_written_vote_copy_sources", written_vote_copy.list_written_vote_copy_sources)
    response = client.get("/api/admin/problems/written-vote-configs")
    assert response.status_code == 200
    if expected is None:
        assert response.json["problems"] == []
    else:
        assert response.json["problems"] == [{
            "id": 40, "title": "书面题 40", "written_vote_config": expected,
        }]
    assert row == original
    assert connection.closed
    assert statements and all(sql.lstrip().upper().startswith("SELECT ") for sql in statements)
    assert all("SELECT *" not in sql and "written_score_public" not in sql
               and "prompt" not in sql and "content" not in sql for sql in statements)
