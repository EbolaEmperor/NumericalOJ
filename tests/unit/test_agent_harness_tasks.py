from copy import deepcopy
from pathlib import Path
from string import Formatter

import pytest

from oj_modules.tasks.agent import generate_testdata as data_task
from oj_modules.tasks.agent import solve as solve_task
from oj_modules.tasks.agent.harness_runtime import HarnessRunResult


class _FakeCelery:
    def __init__(self):
        self.tasks = {}

    def task(self, **_kwargs):
        return lambda function: function


@pytest.mark.parametrize(
    ("register", "task_name"),
    [
        (
            solve_task.register_agent_solve_problem_task,
            solve_task.AGENT_SOLVE_TASK_NAME,
        ),
        (
            data_task.register_agent_generate_testdata_task,
            data_task.AGENT_GENERATE_TESTDATA_TASK_NAME,
        ),
    ],
)
def test_ordinary_agent_celery_tasks_have_no_total_runtime_limit(
    register,
    task_name,
):
    options = []

    class RecordingCelery:
        tasks = {}

        def task(self, **kwargs):
            options.append(kwargs)
            return lambda function: function

    register(RecordingCelery())

    assert options == [{"bind": True, "name": task_name}]


class _FakeTaskSelf:
    class request:
        id = "testdata-harness-task"


_PROBLEM = {
    "id": 5,
    "type": 1,
    "title": "造数据题",
    "lang": "python",
    "test_code": "# checker begin\n%%user_code_here\n# checker end\n",
    "forbidden_func": "",
    "time_limit_ms": 2000,
    "programming_grading_mode": 1,
}
_ENDPOINT = {
    "id": 8,
    "protocol": "openai",
    "category": "text",
    "base_url": "https://model.example/v1",
    "api_key": "secret",
    "model": "model-a",
    "thinking_enabled": False,
    "thinking_format": "none",
}
_BEFORE_STATE = {"testdata": "old-testdata", "max_score": 1}
_ZIP_RELATIVE_PATH = "agent-output/testdata.zip"


def test_solution_prompt_template_requires_authoritative_problem_identity():
    fields = {
        field_name
        for _, field_name, _, _ in Formatter().parse(
            solve_task.SOLUTION_AGENT_PROMPT,
        )
        if field_name
    }

    assert {"problem_id", "problem_title"} <= fields


@pytest.mark.parametrize("problem_lang", ["", "python", "cpp", "matlab"])
def test_solution_prompt_keeps_other_language_workflow_unchanged(problem_lang):
    expected = solve_task.SOLUTION_AGENT_PROMPT.format(
        problem_id=5,
        problem_title="快照题",
    )

    assert solve_task.build_solution_agent_prompt(
        problem_id=5,
        problem_title="快照题",
        problem_lang=problem_lang,
    ) == expected


@pytest.mark.parametrize("problem_lang", ["lean", "lean4", " LEAN4 "])
def test_solution_prompt_adds_complete_lean4_proof_workflow(problem_lang):
    prompt = solve_task.build_solution_agent_prompt(
        problem_id=5,
        problem_title="Lean 证明题",
        problem_lang=problem_lang,
    )

    assert "`initial_code`" in prompt
    assert "完整答案保存为 `Submission.lean`" in prompt
    assert "自行添加辅助引理或定理" in prompt
    assert "容器内预装的 Lean 4 和 Mathlib" in prompt
    assert "`lean Submission.lean`" in prompt
    assert "`problem submit 5 --code-file Submission.lean`" in prompt
    assert "等待该 submission 进入终态" in prompt
    assert "直到 `Accepted`" in prompt
    for forbidden in ("`sorry`", "`admit`", "`axiom`"):
        assert forbidden in prompt


@pytest.mark.parametrize(
    "filename",
    [
        "../answer.py",
        "/tmp/answer.py",
        ".hidden.py",
        "nested\\answer.py",
        "bad\x00name.py",
        "a" * 253 + ".py",
    ],
)
def test_standard_solution_filename_rejects_unsafe_name(filename):
    with pytest.raises(ValueError, match="文件名无效"):
        data_task._safe_standard_solution_filename(filename, ".py")


def test_standard_solution_filename_accepts_basename_and_has_language_fallback():
    assert data_task._safe_standard_solution_filename(
        "official answer.py", ".py",
    ) == "official answer.py"
    assert data_task._safe_standard_solution_filename("", ".m") == (
        "standard_solution.m"
    )


def _patch_common(monkeypatch, tmp_path, *, problem=None):
    snapshots = []
    monkeypatch.setattr(
        data_task,
        "existing_agent_terminal_result",
        lambda _task_id: None,
    )
    monkeypatch.setattr(data_task, "agent_run_is_canceled", lambda _task_id: False)
    monkeypatch.setattr(data_task, "AGENT_WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setattr(
        data_task,
        "get_user_by_username",
        lambda _username: {"id": 3, "is_admin": 1},
    )
    monkeypatch.setattr(
        data_task,
        "get_problem",
        lambda _problem_id: dict(problem or _PROBLEM),
    )
    monkeypatch.setattr(
        data_task,
        "get_problem_testdata_state",
        lambda _problem_id: dict(_BEFORE_STATE),
    )
    monkeypatch.setattr(
        data_task,
        "resolve_launch_endpoint",
        lambda *_args, **_kwargs: dict(_ENDPOINT),
    )
    monkeypatch.setattr(data_task, "prepare_agent_trace_dir", lambda _task_id: None)
    monkeypatch.setattr(data_task, "_publish_agent_trace", lambda _state: None)
    monkeypatch.setattr(
        data_task,
        "generate_initial_agent_session_title",
        lambda *_args, **_kwargs: "生成测试数据",
    )
    monkeypatch.setattr(
        data_task,
        "extract_agent_conclusion",
        lambda _task_id: "测试数据已经生成。",
    )

    def update_state(state, message=None, **updates):
        state.update(updates)
        if message is not None:
            state["message"] = message
        snapshots.append(deepcopy(state))

    monkeypatch.setattr(data_task, "_update_agent_state", update_state)
    return snapshots


def _invoke_task(*, point_count=2, standard_filename="official answer.py"):
    task = data_task.register_agent_generate_testdata_task(_FakeCelery())
    return task(
        _FakeTaskSelf(),
        5,
        "admin",
        point_count,
        "print(1)",
        "覆盖零和最大值",
        standard_filename,
        "codex",
        8,
        "session-cookie",
        "numoj_session",
    )


def _successful_harness_result(payload=b"staged-zip"):
    return HarnessRunResult(
        returncode=0,
        timed_out=False,
        stdout="",
        stderr="",
        artifacts={_ZIP_RELATIVE_PATH: payload},
        native_session_id="11111111-1111-1111-1111-111111111111",
    )


def test_testdata_redelivery_exits_before_creating_workspace(monkeypatch):
    monkeypatch.setattr(
        data_task,
        "existing_agent_terminal_result",
        lambda task_id: {
            "success": False,
            "canceled": True,
            "message": "任务已由管理员终止",
            "task_id": task_id,
        },
    )
    monkeypatch.setattr(
        data_task,
        "prepare_agent_trace_dir",
        lambda _task_id: pytest.fail("已终止任务不得重新创建工作目录"),
    )

    result = _invoke_task()

    assert result["success"] is False
    assert result["canceled"] is True


def test_testdata_unhandled_worker_error_projects_failed_session(
    monkeypatch,
    tmp_path,
):
    snapshots = _patch_common(monkeypatch, tmp_path)
    monkeypatch.setattr(
        data_task,
        "get_user_by_username",
        lambda _username: (_ for _ in ()).throw(RuntimeError("database offline")),
    )

    result = _invoke_task()

    assert result["success"] is False
    assert "worker 异常" in result["message"]
    assert snapshots[-1]["status"] == "Failed"
    assert snapshots[-1]["stage"] == "finished"
    assert snapshots[-1]["session_id"] == "testdata-harness-task"


def test_testdata_cancellation_after_parse_prevents_publish(monkeypatch, tmp_path):
    _patch_common(monkeypatch, tmp_path)
    cancellation_checks = iter([False, False, True])
    monkeypatch.setattr(
        data_task,
        "agent_run_is_canceled",
        lambda _task_id: next(cancellation_checks),
    )
    monkeypatch.setattr(
        data_task,
        "run_agent_harness",
        lambda **_kwargs: _successful_harness_result(),
    )
    monkeypatch.setattr(
        data_task,
        "parse_testdata_zip",
        lambda *_args, **_kwargs: {
            "count": 2,
            "testdata": [
                {"input": "0", "output": "0"},
                {"input": "1", "output": "1"},
            ],
        },
    )
    monkeypatch.setattr(
        data_task,
        "publish_staged_testdata",
        lambda *_args, **_kwargs: pytest.fail("终止后不得发布测试数据"),
    )

    result = _invoke_task()

    assert result["success"] is False
    assert result["canceled"] is True


def test_testdata_task_exports_parses_then_publishes(
        monkeypatch, tmp_path):
    snapshots = _patch_common(monkeypatch, tmp_path)
    payload = b"host-owned-staged-zip"
    rows = [
        {"input": "0", "output": "0"},
        {"input": "9", "output": "81"},
    ]
    calls = []
    harness_calls = []

    monkeypatch.setattr(
        data_task,
        "run_agent_harness",
        lambda **kwargs: (
            harness_calls.append(kwargs)
            or _successful_harness_result(payload)
        ),
    )

    def fake_parse(zip_path, extract_dir):
        calls.append("parse")
        archive = Path(zip_path)
        assert archive.read_bytes() == payload
        assert archive.stat().st_mode & 0o777 == 0o600
        assert Path(extract_dir).parent == archive.parent
        return {"count": 2, "testdata": rows}

    def fake_publish(
        problem_id,
        *,
        before_state,
        testdata,
        agent_task_id,
        agent_completion_message,
    ):
        calls.append("publish")
        assert problem_id == 5
        assert before_state == _BEFORE_STATE
        assert testdata is rows
        assert agent_task_id == "testdata-harness-task"
        assert agent_completion_message == (
            "测试数据格式检查通过并已发布，共 2 个测试点"
        )
        return True

    monkeypatch.setattr(data_task, "parse_testdata_zip", fake_parse)
    monkeypatch.setattr(data_task, "publish_staged_testdata", fake_publish)

    result = _invoke_task()

    assert result == {
        "success": True,
        "message": "测试数据格式检查通过并已发布，共 2 个测试点",
        "task_id": "testdata-harness-task",
        "test_point_count": 2,
    }
    assert calls == ["parse", "publish"]
    assert len(harness_calls) == 1
    harness_call = harness_calls[0]
    assert harness_call["task_kind"] == "testdata"
    assert harness_call["session_cookie"] == "session-cookie"
    assert harness_call["session_cookie_name"] == "numoj_session"
    assert harness_call["workspace_files"] == {
        "task-input/official answer.py": "print(1)",
        "task-input/problem_interactor.py": _PROBLEM["test_code"],
    }
    assert harness_call["artifact_files"] == (_ZIP_RELATIVE_PATH,)
    assert callable(harness_call["cancel_check"])
    assert snapshots[-1]["status"] == "Completed"
    assert snapshots[-1]["stage"] == "finished"
    assert snapshots[-1]["test_point_count"] == 2
    assert snapshots[-1]["title"] == "生成测试数据"
    assert snapshots[-1]["native_session_id"] == (
        "11111111-1111-1111-1111-111111111111"
    )
    assert snapshots[-1]["conclusion"] == "测试数据已经生成。"
    assert "events" not in snapshots[-1]
    assert list(tmp_path.iterdir()) == []


def test_testdata_task_rejects_wrong_point_count_before_publish(
        monkeypatch, tmp_path):
    _patch_common(monkeypatch, tmp_path)
    monkeypatch.setattr(
        data_task,
        "run_agent_harness",
        lambda **_kwargs: _successful_harness_result(),
    )
    monkeypatch.setattr(
        data_task,
        "parse_testdata_zip",
        lambda *_args, **_kwargs: {
            "count": 1,
            "testdata": [{"input": "0", "output": "0"}],
        },
    )
    monkeypatch.setattr(
        data_task,
        "publish_staged_testdata",
        lambda *_args, **_kwargs: pytest.fail("数量不符时不得发布"),
    )

    result = _invoke_task(point_count=2)

    assert result["success"] is False
    assert "要求 2 个测试点，实际生成 1 个" in result["message"]


def test_testdata_task_reports_publish_cas_conflict(monkeypatch, tmp_path):
    snapshots = _patch_common(monkeypatch, tmp_path)
    rows = [
        {"input": "0", "output": "0"},
        {"input": "9", "output": "81"},
    ]
    publish_calls = []
    monkeypatch.setattr(
        data_task,
        "run_agent_harness",
        lambda **_kwargs: _successful_harness_result(),
    )
    monkeypatch.setattr(
        data_task,
        "parse_testdata_zip",
        lambda *_args, **_kwargs: {"count": 2, "testdata": rows},
    )
    monkeypatch.setattr(
        data_task,
        "publish_staged_testdata",
        lambda problem_id, **kwargs: (
            publish_calls.append((problem_id, kwargs)) or False
        ),
    )

    result = _invoke_task()

    assert result["success"] is False
    assert "其他管理员修改" in result["message"]
    assert publish_calls == [(5, {
        "before_state": _BEFORE_STATE,
        "testdata": rows,
        "agent_task_id": "testdata-harness-task",
        "agent_completion_message": (
            "测试数据格式检查通过并已发布，共 2 个测试点"
        ),
    })]
    assert snapshots[-1]["status"] == "Failed"
    assert snapshots[-1]["stage"] == "finished"
    assert "events" not in snapshots[-1]


def test_testdata_task_harness_exception_never_parses_or_publishes(
        monkeypatch, tmp_path):
    _patch_common(monkeypatch, tmp_path)

    def fail_harness(**_kwargs):
        raise RuntimeError("容器异常退出")

    monkeypatch.setattr(data_task, "run_agent_harness", fail_harness)
    monkeypatch.setattr(
        data_task,
        "parse_testdata_zip",
        lambda *_args, **_kwargs: pytest.fail("harness 异常时不得解析"),
    )
    monkeypatch.setattr(
        data_task,
        "publish_staged_testdata",
        lambda *_args, **_kwargs: pytest.fail("harness 异常时不得发布"),
    )

    result = _invoke_task()

    assert result["success"] is False
    assert "容器异常退出" in result["message"]


@pytest.mark.parametrize(
    ("returncode", "timed_out", "message"),
    [
        (23, False, "harness 异常退出（23）"),
        (-9, True, "harness 超时"),
    ],
)
def test_testdata_task_nonzero_harness_result_never_publishes(
        monkeypatch, tmp_path, returncode, timed_out, message):
    _patch_common(monkeypatch, tmp_path)
    monkeypatch.setattr(
        data_task,
        "run_agent_harness",
        lambda **_kwargs: HarnessRunResult(
            returncode=returncode,
            timed_out=timed_out,
            stdout="",
            stderr="boom",
            artifacts={_ZIP_RELATIVE_PATH: b"untrusted"},
        ),
    )
    monkeypatch.setattr(
        data_task,
        "parse_testdata_zip",
        lambda *_args, **_kwargs: pytest.fail("非零退出时不得解析产物"),
    )
    monkeypatch.setattr(
        data_task,
        "publish_staged_testdata",
        lambda *_args, **_kwargs: pytest.fail("非零退出时不得发布"),
    )

    result = _invoke_task()

    assert result["success"] is False
    assert message in result["message"]


def test_testdata_task_never_publishes_without_native_session(
        monkeypatch, tmp_path):
    snapshots = _patch_common(monkeypatch, tmp_path)
    monkeypatch.setattr(
        data_task,
        "run_agent_harness",
        lambda **_kwargs: HarnessRunResult(
            returncode=0,
            timed_out=False,
            stdout="",
            stderr="",
            artifacts={_ZIP_RELATIVE_PATH: b"untrusted"},
        ),
    )
    monkeypatch.setattr(
        data_task,
        "parse_testdata_zip",
        lambda *_args, **_kwargs: pytest.fail("无原生会话时不得解析产物"),
    )
    monkeypatch.setattr(
        data_task,
        "publish_staged_testdata",
        lambda *_args, **_kwargs: pytest.fail("无原生会话时不得发布"),
    )

    result = _invoke_task()

    assert result["success"] is False
    assert "未记录可恢复" in result["message"]
    assert snapshots[-1]["status"] == "Failed"


@pytest.mark.parametrize("grading_mode", [2, 3])
def test_testdata_task_only_allows_standard_test_point_grading_mode(
        monkeypatch, tmp_path, grading_mode):
    problem = dict(_PROBLEM, programming_grading_mode=grading_mode)
    _patch_common(monkeypatch, tmp_path, problem=problem)
    monkeypatch.setattr(
        data_task,
        "run_agent_harness",
        lambda **_kwargs: pytest.fail("非 mode 1 不得启动 harness"),
    )
    monkeypatch.setattr(
        data_task,
        "publish_staged_testdata",
        lambda *_args, **_kwargs: pytest.fail("非 mode 1 不得发布"),
    )

    result = _invoke_task()

    assert result["success"] is False
    assert "仅支持标准测试点评分模式" in result["message"]


def _patch_harness_solution_task(monkeypatch, *, submissions):
    snapshots = []
    reads = iter(submissions)
    monkeypatch.setattr(
        solve_task,
        "existing_agent_terminal_result",
        lambda _task_id: None,
    )
    monkeypatch.setattr(solve_task, "agent_run_is_canceled", lambda _task_id: False)
    monkeypatch.setattr(solve_task, "prepare_agent_trace_dir", lambda _task_id: None)
    monkeypatch.setattr(solve_task, "_publish_agent_trace", lambda _state: None)
    monkeypatch.setattr(
        solve_task,
        "generate_initial_agent_session_title",
        lambda *_args, **_kwargs: "解决快照题",
    )
    monkeypatch.setattr(
        solve_task,
        "extract_agent_conclusion",
        lambda _task_id: "题目已经解决。",
    )

    def update_state(state, message=None, **updates):
        state.update(updates)
        if message is not None:
            state["message"] = message
        snapshots.append(deepcopy(state))

    monkeypatch.setattr(solve_task, "_update_agent_state", update_state)
    monkeypatch.setattr(
        solve_task,
        "get_user_by_username",
        lambda _username: {"id": 3, "is_admin": 1},
    )
    monkeypatch.setattr(
        solve_task,
        "get_problem",
        lambda _problem_id: {
            "id": 5,
            "type": 1,
            "title": "快照题",
            "lang": "python",
        },
    )
    monkeypatch.setattr(
        solve_task,
        "get_submissions_by_user_and_problem",
        lambda *_args: next(reads),
    )
    return snapshots


def test_solution_redelivery_exits_before_creating_workspace(monkeypatch):
    monkeypatch.setattr(
        solve_task,
        "existing_agent_terminal_result",
        lambda task_id: {
            "success": False,
            "canceled": True,
            "message": "任务已由管理员终止",
            "task_id": task_id,
        },
    )
    monkeypatch.setattr(
        solve_task,
        "prepare_agent_trace_dir",
        lambda _task_id: pytest.fail("已终止任务不得重新创建工作目录"),
    )
    task = solve_task.register_agent_solve_problem_task(_FakeCelery())

    result = task(
        _FakeTaskSelf(), 5, "admin", "codex", 31, "session-cookie",
    )

    assert result["success"] is False
    assert result["canceled"] is True


def test_solution_unhandled_worker_error_projects_failed_session(monkeypatch):
    snapshots = _patch_harness_solution_task(monkeypatch, submissions=[])
    monkeypatch.setattr(
        solve_task,
        "get_user_by_username",
        lambda _username: (_ for _ in ()).throw(RuntimeError("database offline")),
    )
    task = solve_task.register_agent_solve_problem_task(_FakeCelery())

    result = task(
        _FakeTaskSelf(), 5, "admin", "codex", 31, "session-cookie",
    )

    assert result["success"] is False
    assert "worker 异常" in result["message"]
    assert snapshots[-1]["status"] == "Failed"
    assert snapshots[-1]["stage"] == "finished"
    assert snapshots[-1]["session_id"] == "testdata-harness-task"


def test_solution_task_uses_selected_endpoint(monkeypatch):
    _patch_harness_solution_task(monkeypatch, submissions=[[]])
    resolutions = []
    runs = []
    prompt_requests = []
    endpoint = {**_ENDPOINT, "id": 31, "model": "selected-model"}
    monkeypatch.setattr(
        solve_task,
        "build_solution_agent_prompt",
        lambda **kwargs: (
            prompt_requests.append(kwargs) or "rendered-solution-prompt"
        ),
    )
    monkeypatch.setattr(
        solve_task,
        "resolve_launch_endpoint",
        lambda harness, endpoint_id, **kwargs: (
            resolutions.append((harness, endpoint_id, kwargs)) or endpoint
        ),
    )
    monkeypatch.setattr(
        solve_task,
        "run_agent_harness",
        lambda **kwargs: (
            runs.append(kwargs)
            or HarnessRunResult(0, False, "", "")
        ),
    )

    task = solve_task.register_agent_solve_problem_task(_FakeCelery())
    result = task(
        _FakeTaskSelf(), 5, "admin", "codex", 31, "session-cookie",
        "numoj_session",
    )

    assert result["success"] is False
    assert resolutions == [("codex", 31, {"include_secret": True})]
    assert runs[0]["harness"] == "codex"
    assert runs[0]["session_id"] == "testdata-harness-task"
    assert runs[0]["access_role"] == "user"
    assert runs[0]["problem_id"] == 5
    assert runs[0]["session_cookie"] == "session-cookie"
    assert runs[0]["session_cookie_name"] == "numoj_session"
    assert callable(runs[0]["cancel_check"])
    assert runs[0]["prompt"] == "rendered-solution-prompt"
    assert prompt_requests == [{
        "problem_id": 5,
        "problem_title": "快照题",
        "problem_lang": "python",
    }]


def test_solution_task_rejects_unavailable_selected_endpoint(monkeypatch):
    snapshots = _patch_harness_solution_task(monkeypatch, submissions=[])
    runs = []
    monkeypatch.setattr(
        solve_task,
        "resolve_launch_endpoint",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ValueError("所选 LLM 节点已删除")
        ),
    )
    monkeypatch.setattr(
        solve_task,
        "run_agent_harness",
        lambda **kwargs: runs.append(kwargs),
    )

    task = solve_task.register_agent_solve_problem_task(_FakeCelery())
    result = task(
        _FakeTaskSelf(), 5, "admin", "codex", 31, "session-cookie",
    )

    assert result["success"] is False
    assert "已删除" in result["message"]
    assert runs == []
    assert snapshots[-1]["status"] == "Failed"
    assert snapshots[-1]["stage"] == "finished"
    assert "events" not in snapshots[-1]


def test_solution_task_succeeds_only_for_relay_created_accepted_submission(
    monkeypatch,
):
    _patch_harness_solution_task(
        monkeypatch,
        submissions=[[
            {"id": 76, "status": "Accepted", "score": 10},
            {"id": 77, "status": "Accepted", "score": 10},
        ]],
    )
    endpoint = {**_ENDPOINT, "id": 31, "model": "selected-model"}
    monkeypatch.setattr(
        solve_task,
        "resolve_launch_endpoint",
        lambda *_args, **_kwargs: endpoint,
    )
    monkeypatch.setattr(
        solve_task,
        "run_agent_harness",
        lambda **_kwargs: HarnessRunResult(
            0,
            False,
            "",
            "",
            created_submission_ids=(77,),
            native_session_id="77777777-7777-7777-7777-777777777777",
        ),
    )

    task = solve_task.register_agent_solve_problem_task(_FakeCelery())
    result = task(
        _FakeTaskSelf(), 5, "admin", "codex", 31, "session-cookie",
    )

    assert result["success"] is True
    assert result["final_submission_id"] == 77


def test_solution_task_cannot_complete_without_native_session(monkeypatch):
    snapshots = _patch_harness_solution_task(
        monkeypatch,
        submissions=[[{"id": 77, "status": "Accepted", "score": 10}]],
    )
    monkeypatch.setattr(
        solve_task,
        "resolve_launch_endpoint",
        lambda *_args, **_kwargs: {**_ENDPOINT, "id": 31},
    )
    monkeypatch.setattr(
        solve_task,
        "run_agent_harness",
        lambda **_kwargs: HarnessRunResult(
            0,
            False,
            "",
            "",
            created_submission_ids=(77,),
        ),
    )

    task = solve_task.register_agent_solve_problem_task(_FakeCelery())
    result = task(
        _FakeTaskSelf(), 5, "admin", "codex", 31, "session-cookie",
    )

    assert result["success"] is False
    assert "未记录可恢复" in result["message"]
    assert snapshots[-1]["status"] == "Failed"
    assert snapshots[-1]["final_submission_id"] == 77
