"""完整作品自有的输入、执行续调、成绩与公开/私有服务边界。"""

import base64
import heapq
import importlib.util
from io import BytesIO
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "vibehub_examples" / "dynamic-balance"
SOURCE = "double step(int x) { A.insert(x); return A.top(); }"


@pytest.fixture
def balance(monkeypatch):
    monkeypatch.syspath_prepend(str(EXAMPLE))
    spec = importlib.util.spec_from_file_location("dynamic_balance_example", EXAMPLE / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def command_result(returncode=0, stdout="", stderr=""):
    return {"returncode": returncode, "stdout_b64": base64.b64encode(stdout.encode()).decode(),
            "stderr_b64": base64.b64encode(stderr.encode()).decode(),
            "stdout_truncated": False, "stderr_truncated": False}


def reference_execution(inputs, *, wrong_at=None):
    """独立构造合法操作轨迹，不使用被测作品的中位数或重放实现。"""
    left, right, seen, output = [], [], [], []
    for index, value in enumerate(inputs):
        operations = []
        if not left or value <= -left[0]:
            heapq.heappush(left, -value)
            operations.append(f"A I {value}")
        else:
            heapq.heappush(right, value)
            operations.append(f"B I {value}")
        if len(left) > len(right) + 1:
            moved = -heapq.heappop(left)
            heapq.heappush(right, moved)
            operations.extend([f"A P {moved}", f"B I {moved}"])
        elif len(right) > len(left):
            moved = heapq.heappop(right)
            heapq.heappush(left, -moved)
            operations.extend([f"B P {moved}", f"A I {moved}"])
        seen.append(value)
        ordered = sorted(seen)
        median = (ordered[(len(seen) - 1) // 2] + ordered[len(seen) // 2]) / 2
        returned = median + (1 if index == wrong_at else 0)
        output.append(f"ROUND {index} {returned} {len(operations)}")
        output.extend(operations)
    return {"compile": command_result(), "run": command_result(stdout="\n".join(output) + "\n")}


def answer_only_execution(inputs, heap_usage):
    seen, output = [], []
    for index, value in enumerate(inputs):
        seen.append(value)
        ordered = sorted(seen)
        median = (ordered[(len(seen) - 1) // 2] + ordered[len(seen) // 2]) / 2
        operations = {
            "unused": [],
            "duplicates": [f"A I {value}", f"B I {value}"],
            "one_heap": [f"A I {value}"],
            "discarded": [f"A I {value}", f"A P {value}"],
        }[heap_usage]
        output.extend([f"ROUND {index} {median} {len(operations)}", *operations])
    return {"compile": command_result(), "run": command_result(stdout="\n".join(output) + "\n")}


def request_inputs(request):
    numbers = [int(value) for value in request["run"]["stdin"].split()]
    assert numbers[0] == len(numbers) - 1
    return numbers[1:]


def resume_step(balance, context, request, execution_result):
    return balance.step(context, {}, {}, continuation=request["continuation"], execution_result=execution_result)


def resume_grade(balance, context, request, execution_result):
    return balance.grade(context, [], continuation=request["continuation"], execution_result=execution_result)


def private_post(balance, path, payload):
    handler = object.__new__(balance.EducationHandler)
    body = json.dumps(payload).encode()
    handler.path = path
    handler.headers = {"Content-Length": str(len(body))}
    handler.rfile = BytesIO(body)
    handler.wfile = BytesIO()
    responses = []
    handler.send_response = responses.append
    handler.send_header = lambda *_args: None
    handler.end_headers = lambda: None
    handler.do_POST()
    return responses[0], json.loads(handler.wfile.getvalue())


def test_manifest_declares_only_the_generic_private_education_protocol():
    manifest = json.loads((EXAMPLE / "vibehub.json").read_text())
    assert manifest["kind"] == "edu"
    assert manifest["education"] == {"protocol": "vibehub-edu/1", "socket_path": "/run/vibehub/edu.sock"}
    assert (EXAMPLE / manifest["cover_image"]).is_file()


def test_start_owns_a_deterministic_public_sequence_and_never_exposes_hidden_inputs(balance):
    context = {"challenge_seed": "example", "assignment_id": 42, "parameters": {"inputs": [123456789]}}
    initial = balance.start(context)
    assert initial == balance.start(context)
    assert initial["view"]["inputs"] == balance.practice_inputs(context)
    assert initial["view"]["inputs"] != [123456789]
    assert len(initial["view"]["inputs"]) == 24
    assert "double step(int x)" in initial["view"]["source"]
    assert initial["view"]["assignment_id"] == 42
    assert "user_id" not in initial["view"] and "challenge_seed" not in initial["view"]
    assert balance.hidden_inputs(context) != initial["view"]["inputs"]
    assert len(balance.hidden_inputs(context)) == 129
    assert balance.hidden_inputs(context)[:4] == [999999999, 1000000000, -1000000000, -999999999]
    assert initial != balance.start({"challenge_seed": "other"})


@pytest.mark.parametrize("extra", ["execution", "execution_result", "continuation", "score", "completed"])
def test_action_cannot_supply_execution_or_score_fields(balance, extra):
    state = balance.start({"challenge_seed": "example"})["state"]
    with pytest.raises(ValueError, match="只接受"):
        balance.step({}, state, {"type": "run_code", "source": SOURCE, extra: {"passed": 100}})


@pytest.mark.parametrize("action", [{"type": "completed", "score": 100}, {"type": "run_code"},
    {"type": "run_code", "source": None}, {"type": "run_code", "source": " "},
    {"type": "run_code", "source": "x" * 65537}, {"type": "run_code", "source": "a\x00b"}])
def test_invalid_actions_cannot_request_execution(balance, action):
    with pytest.raises(ValueError):
        balance.step({}, balance.start({})["state"], action)


def test_trial_requests_generic_execution_and_finishes_from_private_results(balance):
    context = {"challenge_seed": "example", "assignment_id": 8,
               "execution": {"compiled": True, "passed": 999, "score": 100}}
    state = balance.start(context)["state"]
    request = balance.step(context, state, {"type": "run_code", "source": SOURCE})
    assert set(request) == {"execute", "continuation"}
    assert request_inputs(request["execute"]) == state["inputs"]
    assert "execution" not in request and state["execution"] is None
    updated = resume_step(balance, context, request, reference_execution(state["inputs"]))
    execution = updated["view"]["execution"]
    assert execution["compiled"] is True
    assert execution["passed"] == execution["total"] == len(state["inputs"])
    assert execution["rounds"][1]["expected"] == execution["rounds"][1]["returned"] == 5.5
    assert updated["view"]["source"] == SOURCE and updated["view"]["assignment_id"] == 8
    assert state["execution"] is None


def test_trial_failure_keeps_the_correct_prefix_and_current_exception_scene(balance):
    context = {"challenge_seed": "example"}
    state = balance.start(context)["state"]
    request = balance.step(context, state, {"type": "run_code", "source": SOURCE})
    raw = "ROUND 0 7 2\nA I 7\nA T 7\nERROR 1 1\nA I 4\n"
    result = resume_step(balance, context, request, {"compile": command_result(),
        "run": command_result(3, raw, "B.top()：不能读取空堆的堆顶")})["view"]["execution"]
    assert result["passed"] == 1 and result["total"] == len(state["inputs"])
    assert result["rounds"][-1]["left_heap"] == [7, 4]
    assert result["rounds"][-1]["operations"] == [{"heap": "A", "type": "insert", "value": 4}]
    assert result["rounds"][-1]["returned"] is None


def test_grade_uses_last_frozen_source_and_its_own_hidden_tests(balance):
    context = {"challenge_seed": "example", "parameters": {"inputs": [7]},
               "execution": {"passed": 100, "total": 100}}
    actions = [{"seq": 1, "action": {"type": "run_code", "source": "double step(int x){return 0;}"}},
               {"seq": 2, "action": {"type": "run_code", "source": SOURCE}}]
    request = balance.grade(context, actions)
    assert request["execute"]["files"]["student.cpp"].endswith(SOURCE)
    inputs = request_inputs(request["execute"])
    assert inputs == balance.hidden_inputs(context)
    assert inputs != balance.practice_inputs(context)
    assert "inputs" not in request["continuation"]
    result = resume_grade(balance, context, request, reference_execution(inputs))
    assert result == {"score_bp": 10000, "verdict": "passed",
        "metrics": {"passed_rounds": 129, "total_rounds": 129}, "feedback": "隐藏测试通过 129/129 轮。"}
    assert "999999999" not in json.dumps(result)


def test_grade_counts_only_the_correct_prefix_even_if_later_rounds_pass(balance):
    context = {"challenge_seed": "prefix"}
    request = balance.grade(context, [{"action": {"type": "run_code", "source": SOURCE}}])
    inputs = request_inputs(request["execute"])
    result = resume_grade(balance, context, request, reference_execution(inputs, wrong_at=1))
    assert result["score_bp"] == 10000 // 129
    assert result["metrics"] == {"passed_rounds": 1, "total_rounds": 129}
    assert result["verdict"] == "failed"


@pytest.mark.parametrize("heap_usage", ["unused", "duplicates", "one_heap", "discarded"])
def test_trial_and_grade_only_require_correct_medians_regardless_of_heap_strategy(balance, heap_usage):
    context = {"challenge_seed": "answer-only"}
    state = balance.start(context)["state"]
    action = {"type": "run_code", "source": SOURCE}
    trial = balance.step(context, state, action)
    updated = resume_step(balance, context, trial, answer_only_execution(state["inputs"], heap_usage))
    execution = updated["view"]["execution"]
    assert execution["passed"] == execution["total"] == 24
    assert all(item["feedback"] == "中位数正确" for item in execution["rounds"])
    final = execution["rounds"][-1]
    if heap_usage in {"unused", "discarded"}:
        assert final["left_heap"] == final["right_heap"] == []
    elif heap_usage == "one_heap":
        assert len(final["left_heap"]) == 24 and final["right_heap"] == []
    else:
        assert len(final["left_heap"]) == len(final["right_heap"]) == 24
    request = balance.grade(context, [{"action": action}])
    hidden = request_inputs(request["execute"])
    result = resume_grade(balance, context, request, answer_only_execution(hidden, heap_usage))
    assert result["verdict"] == "passed" and result["score_bp"] == 10000
    assert result["metrics"] == {"passed_rounds": 129, "total_rounds": 129}


def test_runtime_error_still_prevents_full_credit_after_all_correct_medians(balance):
    context = {"challenge_seed": "runtime-failure"}
    request = balance.grade(context, [{"action": {"type": "run_code", "source": SOURCE}}])
    response = answer_only_execution(request_inputs(request["execute"]), "unused")
    response["run"].update(returncode=3, stderr_b64=base64.b64encode(b"runtime exception").decode())
    result = resume_grade(balance, context, request, response)
    assert result["verdict"] == "failed"
    assert result["score_bp"] == 10000 * 128 // 129
    assert result["metrics"] == {"passed_rounds": 128, "total_rounds": 129}


@pytest.mark.parametrize("returned", ["nan", "-inf", "1e309"])
def test_grade_nonfinite_output_cannot_become_a_score(balance, returned):
    context = {"challenge_seed": "nonfinite"}
    request = balance.grade(context, [{"action": {"type": "run_code", "source": SOURCE}}])
    first_input = request_inputs(request["execute"])[0]
    result = resume_grade(balance, context, request, {"compile": command_result(),
        "run": command_result(stdout=f"ROUND 0 {returned} 1\nA I {first_input}\n")})
    assert result["score_bp"] == 0 and result["verdict"] == "failed"
    assert result["metrics"]["passed_rounds"] == 0
    assert returned not in result["feedback"]


@pytest.mark.parametrize("stderr", ["编译错误", "hidden secret 999999999", "nan"])
def test_grade_failure_does_not_leak_hidden_input_or_program_output(balance, stderr):
    context = {"challenge_seed": "example"}
    request = balance.grade(context, [{"action": {"type": "run_code", "source": SOURCE}}])
    response = {"compile": command_result(1, stderr=stderr)}
    result = resume_grade(balance, context, request, response)
    assert result["score_bp"] == 0 and result["verdict"] == "failed"
    assert stderr not in result["feedback"]
    response = {"compile": command_result(), "run": command_result(3, "ERROR 0 0\n", stderr)}
    result = resume_grade(balance, context, request, response)
    assert result["score_bp"] == 0 and stderr not in result["feedback"]


@pytest.mark.parametrize("actions", [[], [None], [{"action": {"type": "score", "score": 100}}],
    [{"action": {"type": "run_code", "source": SOURCE, "execution_result": {"passed": 129}}}]])
def test_grade_rejects_missing_or_forged_frozen_actions(balance, actions):
    with pytest.raises(ValueError):
        balance.grade({}, actions)


def test_private_http_continuation_completes_both_trial_and_grade(balance):
    context = {"challenge_seed": "http", "assignment_id": 1}
    status, initial = private_post(balance, "/v1/start", {"context": context})
    assert status == 200
    original = {"context": context, "state": initial["state"], "action": {"type": "run_code", "source": SOURCE}}
    status, pending = private_post(balance, "/v1/step", original)
    assert status == 200
    status, trial = private_post(balance, "/v1/step", {"context": context,
        "continuation": pending["continuation"], "execution_result": reference_execution(initial["view"]["inputs"])})
    assert status == 200 and trial["view"]["execution"]["passed"] == 24
    status, pending = private_post(balance, "/v1/grade", {"context": context, "actions": [{"action": original["action"]}]})
    assert status == 200
    status, grade = private_post(balance, "/v1/grade", {"context": context,
        "continuation": pending["continuation"], "execution_result": reference_execution(request_inputs(pending["execute"]))})
    assert status == 200 and grade["score_bp"] == 10000


def test_private_http_rejects_partial_cross_operation_and_fabricated_continuations(balance):
    status, _ = private_post(balance, "/v1/step", {"context": {}, "execution_result": {}})
    assert status == 400
    request = balance.grade({}, [{"action": {"type": "run_code", "source": SOURCE}}])
    status, _ = private_post(balance, "/v1/step", {"context": {}, "continuation": request["continuation"], "execution_result": {}})
    assert status == 400
    status, _ = private_post(balance, "/v1/grade", {"context": {}, "continuation": request["continuation"],
        "execution_result": {"compiled": True, "score": 100, "passed": 129}})
    assert status == 503


def test_public_static_handler_cannot_dispatch_the_private_education_protocol(balance):
    handler = object.__new__(balance.AppHandler)
    errors = []
    handler.send_error = errors.append
    for path in ("/v1/grade", "/v1/step", "/_edu/v1/result"):
        handler.path = path
        handler.do_GET()
    assert errors == [404, 404, 404]
    assert "do_POST" not in balance.AppHandler.__dict__


def test_demo_keeps_visual_playback_and_uses_only_execution_requests():
    source = (EXAMPLE / "app.py").read_text()
    assert "subprocess" not in source and "exec(" not in source
    assert "from backend" not in source and "import backend" not in source
    html = (EXAMPLE / "static" / "index.html").read_text()
    for item in ('id="conveyor"', 'id="heapA"', 'id="heapB"', 'id="runButton"', 'id="submitButton"'):
        assert item in html
    script = (EXAMPLE / "static" / "app.js").read_text()
    playback = (EXAMPLE / "static" / "playback.js").read_text()
    assert "if (!result.passed" in playback
    assert "上浮" in playback and "下沉" in playback
    assert "NumOJHeapPlayback.buildFrames" in script
    assert "NumOJHeapMotion.create" in script
    assert "action: { type: 'run_code', source }" in script
    assert "score: 100" not in script


def test_example_dockerfile_preserves_the_allowed_uid_and_protects_private_work_files():
    from backend.oj_modules.vibehub.runtime import _dockerfile_base_images

    dockerfile = (EXAMPLE / "Dockerfile").read_text()
    assert "COPY --chown=65532:65532 . /app" in dockerfile
    assert "RUN chmod 700 /app" in dockerfile
    assert _dockerfile_base_images(dockerfile, ("numericaloj-vibehub-runtime:1",)) == ("numericaloj-vibehub-runtime:1",)


def test_startup_protects_owned_persistent_data_before_serving(balance, tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir(mode=0o755)
    balance.protect_data_directory(data)
    assert stat.S_IMODE(data.stat().st_mode) == 0o700
    calls = []
    monkeypatch.setattr(balance, "protect_data_directory", lambda: calls.append("protected"))

    class StopBeforeSockets(Exception):
        pass

    def stop_path(*_args):
        assert calls == ["protected"]
        raise StopBeforeSockets

    monkeypatch.setattr(balance, "Path", stop_path)
    with pytest.raises(StopBeforeSockets):
        balance.serve()


def test_local_startup_can_skip_an_absent_data_mount(balance, tmp_path):
    absent = tmp_path / "absent-data"
    balance.protect_data_directory(absent)
    assert not absent.exists()


def test_data_protection_rejects_foreign_owner_and_symlink(balance, tmp_path):
    foreign = SimpleNamespace(lstat=lambda: SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=os.geteuid() + 1),
                              chmod=lambda *_args: pytest.fail("不能修改非作品服务拥有的目录"))
    with pytest.raises(PermissionError, match="作品服务拥有"):
        balance.protect_data_directory(foreign)
    target = tmp_path / "target"
    target.mkdir(mode=0o755)
    link = tmp_path / "data-link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(PermissionError, match="真实目录"):
        balance.protect_data_directory(link)
    assert stat.S_IMODE(target.stat().st_mode) == 0o755


def test_data_permission_change_failure_prevents_startup(balance):
    def denied(*_args):
        raise PermissionError("read-only mount")

    data = SimpleNamespace(lstat=lambda: SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=os.geteuid()), chmod=denied)
    with pytest.raises(PermissionError, match="read-only mount"):
        balance.protect_data_directory(data)
