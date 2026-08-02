# -*- coding: utf-8 -*-

import json
import importlib.util
from argparse import Namespace
from pathlib import Path

import pytest


def _promptly_review_config():
    return json.dumps(
        {
            "brief": "给定 n、k 和数组，输出每个长度为 k 的窗口极差。",
            "prompt_requirements": "需要说明单调队列、下标、过期元素处理和答案来源。",
            "example_replies": [
                "请补充具体算法思路，说明如何维护窗口最大值和最小值。",
                "请说明队列里保存什么，以及窗口移动时如何删除过期元素。",
            ],
        },
        ensure_ascii=False,
    )


def _text_endpoint(endpoint_id=1):
    return {
        "id": endpoint_id,
        "name": f"test-text-{endpoint_id}",
        "category": "text",
        "protocol": "openai",
        "base_url": "https://llm.example/v1",
        "api_key": "test-secret",
        "model": "test-model",
        "thinking_enabled": False,
        "thinking_format": "none",
    }


def test_parse_promptly_review_config_json():
    from oj_modules.promptly_guard import parse_promptly_review_config

    config = parse_promptly_review_config({"programming_grading_prompt": _promptly_review_config()})

    assert config["brief"] == "给定 n、k 和数组，输出每个长度为 k 的窗口极差。"
    assert "单调队列" in config["prompt_requirements"]
    assert len(config["example_replies"]) == 2
    assert config["raw_is_json"] is True


def test_parse_promptly_review_config_plain_text_as_brief():
    from oj_modules.promptly_guard import parse_promptly_review_config

    config = parse_promptly_review_config({"programming_grading_prompt": "Only a brief."})

    assert config["brief"] == "Only a brief."
    assert config["prompt_requirements"] == ""
    assert config["example_replies"] == []
    assert config["raw_is_json"] is False


def test_problem_api_returns_promptly_review_config():
    from oj_modules.api.problem_api import _promptly_review_config_from_prompt

    config = _promptly_review_config_from_prompt(_promptly_review_config())

    assert config["brief"] == "给定 n、k 和数组，输出每个长度为 k 的窗口极差。"
    assert "单调队列" in config["prompt_requirements"]
    assert len(config["example_replies"]) == 2
    assert config["raw_is_json"] is True


def _load_numoj_admin_cli_module():
    root = Path(__file__).resolve().parents[2]
    path = root / "skills" / "numoj-admin" / "scripts" / "numoj_admin.py"
    spec = importlib.util.spec_from_file_location("numoj_admin_cli_for_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _load_numoj_user_cli_module():
    root = Path(__file__).resolve().parents[2]
    path = root / "skills" / "numoj-user" / "scripts" / "numoj_user.py"
    spec = importlib.util.spec_from_file_location("numoj_user_cli_for_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class _FakeCelery:
    def task(self, **_kwargs):
        def deco(fn):
            return fn
        return deco


def test_admin_cli_builds_promptly_review_json_from_structured_args():
    cli = _load_numoj_admin_cli_module()
    args = Namespace(
        programming_grading_prompt=None,
        promptly_brief="题意",
        promptly_requirements="要求",
        promptly_example_reply=["回复 1", "回复 2"],
        promptly_example_replies_json=None,
        clear_promptly_example_replies=False,
    )

    payload = json.loads(cli.build_promptly_grading_prompt_arg(args))

    assert payload == {
        "brief": "题意",
        "prompt_requirements": "要求",
        "example_replies": ["回复 1", "回复 2"],
    }


def test_admin_cli_edit_preserves_unspecified_promptly_fields():
    cli = _load_numoj_admin_cli_module()
    current = {
        "promptly_review_config": {
            "brief": "旧题意",
            "prompt_requirements": "旧要求",
            "example_replies": ["旧回复"],
        }
    }
    args = Namespace(
        programming_grading_prompt=None,
        promptly_brief=None,
        promptly_requirements="新要求",
        promptly_example_reply=None,
        promptly_example_replies_json=None,
        clear_promptly_example_replies=False,
    )

    payload = json.loads(cli.build_promptly_grading_prompt_arg(args, current))

    assert payload == {
        "brief": "旧题意",
        "prompt_requirements": "新要求",
        "example_replies": ["旧回复"],
    }


def test_review_promptly_student_prompt_accepts_nice(monkeypatch):
    from oj_modules import ai_utils

    captured = {}

    def fake_call_llm_text(prompt_text, _endpoint, **kwargs):
        captured["prompt_text"] = prompt_text
        captured["system_prompt"] = kwargs.get("system_prompt")
        return '{"nice": true}'

    monkeypatch.setattr(ai_utils, "_call_llm_text", fake_call_llm_text)

    nice, reply = ai_utils.review_promptly_student_prompt(
        problem={"programming_grading_prompt": _promptly_review_config()},
        student_prompt="用两个单调队列维护最大最小值。",
        endpoint=_text_endpoint(),
    )

    assert nice is True
    assert reply == ""
    assert "给定 n、k 和数组" in captured["system_prompt"]
    assert "需要说明单调队列" in captured["system_prompt"]
    assert "请补充具体算法思路" in captured["system_prompt"]
    assert "用两个单调队列维护最大最小值" in captured["prompt_text"]


def test_review_promptly_student_prompt_rejects_with_reply(monkeypatch):
    from oj_modules import ai_utils

    def fake_call_llm_text(prompt_text, _endpoint, **kwargs):
        return '{"nice": false, "reply": "请说明具体使用的数据结构和更新规则。"}'

    monkeypatch.setattr(ai_utils, "_call_llm_text", fake_call_llm_text)

    nice, reply = ai_utils.review_promptly_student_prompt(
        problem={"programming_grading_prompt": _promptly_review_config()},
        student_prompt="帮我写 O(n) 算法。",
        endpoint=_text_endpoint(),
    )

    assert nice is False
    assert reply == "请说明具体使用的数据结构和更新规则。"


def test_review_promptly_student_prompt_fake_env(monkeypatch):
    from oj_modules import ai_utils

    monkeypatch.setenv("NUMOJ_FAKE_PROMPTLY_REVIEW_REQUIRED_TERMS", '["monotonic deque", "expired index"]')
    monkeypatch.setenv("NUMOJ_FAKE_PROMPTLY_REVIEW_REPLY", "Please explain the required algorithm.")

    nice, reply = ai_utils.review_promptly_student_prompt(
        problem={"programming_grading_prompt": _promptly_review_config()},
        student_prompt="Use a monotonic deque and remove each expired index.",
        model_spec="",
    )
    assert nice is True
    assert reply == ""

    nice, reply = ai_utils.review_promptly_student_prompt(
        problem={"programming_grading_prompt": _promptly_review_config()},
        student_prompt="Please write an O(n) algorithm.",
        model_spec="",
    )
    assert nice is False
    assert reply == "Please explain the required algorithm."


def test_submission_status_snapshot_exposes_promptly_reply():
    from oj_modules import db_services

    snapshot = db_services._build_submission_status_snapshot_from_row(
        {
            "id": 12,
            "username": "alice",
            "problem_id": 34,
            "problem_type": 1,
            "status": "Unaccepted",
            "score": 0,
            "test_points": "",
            "generated_from_prompt": 1,
            "prompt_generation_error": "请补充单调队列如何维护窗口。",
        }
    )

    assert snapshot["generated_from_prompt"] is True
    assert snapshot["prompt_generation_error"] == "请补充单调队列如何维护窗口。"
    assert snapshot["promptly_review_reply"] == "请补充单调队列如何维护窗口。"


def test_submission_detail_payload_exposes_promptly_reply_alias():
    from oj_modules.api.submission_api import _submission_detail_payload

    payload = _submission_detail_payload(
        {
            "id": 12,
            "username": "alice",
            "problem_id": 34,
            "problem_title": "Promptly",
            "problem_type": 1,
            "code": "",
            "prompt_text": "帮我写 O(n) 算法",
            "generated_from_prompt": 1,
            "prompt_generation_error": "请说明具体算法思路。",
            "status": "Unaccepted",
            "score": 0,
            "created_at": None,
            "test_points": [],
        }
    )

    assert payload["prompt_generation_error"] == "请说明具体算法思路。"
    assert payload["promptly_review_reply"] == "请说明具体算法思路。"


def test_numoj_user_wait_promptly_review_result_returns_reply():
    cli = _load_numoj_user_cli_module()

    class FakeResponse:
        status_code = 200
        headers = {"Content-Type": "application/json"}
        text = ""
        reason = "OK"

        def __init__(self, payload):
            self._payload = payload

        def json(self):
            return self._payload

    class FakeClient:
        def __init__(self):
            self.payloads = [
                {"status": "Generating", "promptly_review_reply": ""},
                {"status": "Unaccepted", "promptly_review_reply": "请补充关键边界处理。"},
            ]

        def request(self, method, path):
            assert method == "GET"
            assert path == "/submission_status/99"
            return FakeResponse(self.payloads.pop(0))

    result = cli.wait_promptly_review_result(
        FakeClient(),
        99,
        timeout_seconds=1.0,
        poll_interval_seconds=0.1,
    )

    assert result["done"] is True
    assert result["accepted"] is False
    assert result["reply"] == "请补充关键边界处理。"
    assert result["submission_status"]["status"] == "Unaccepted"


def test_numoj_user_wait_promptly_review_result_treats_judge_failure_as_review_success():
    cli = _load_numoj_user_cli_module()

    class FakeResponse:
        status_code = 200
        headers = {"Content-Type": "application/json"}
        text = ""
        reason = "OK"

        def json(self):
            return {
                "status": "Unaccepted",
                "prompt_generation_error": "",
                "promptly_review_reply": "",
            }

    class FakeClient:
        def request(self, method, path):
            assert method == "GET"
            assert path == "/submission_status/101"
            return FakeResponse()

    result = cli.wait_promptly_review_result(
        FakeClient(),
        101,
        timeout_seconds=1.0,
        poll_interval_seconds=0.1,
    )

    assert result["done"] is True
    assert result["accepted"] is True
    assert result["reply"] == ""
    assert result["status"] == "Unaccepted"


def test_numoj_admin_wait_promptly_review_result_returns_reply():
    cli = _load_numoj_admin_cli_module()

    class FakeResponse:
        status_code = 200
        headers = {"Content-Type": "application/json"}
        text = ""
        reason = "OK"

        def __init__(self, payload):
            self._payload = payload

        def json(self):
            return self._payload

    class FakeClient:
        def __init__(self):
            self.payloads = [
                {"status": "Generating", "prompt_generation_error": ""},
                {"status": "Unaccepted", "prompt_generation_error": "请补充关键边界处理。"},
            ]

        def request(self, method, path):
            assert method == "GET"
            assert path == "/submission_status/100"
            return FakeResponse(self.payloads.pop(0))

    result = cli.wait_promptly_review_result(
        FakeClient(),
        100,
        timeout_seconds=1.0,
        poll_interval_seconds=0.1,
    )

    assert result["done"] is True
    assert result["accepted"] is False
    assert result["reply"] == "请补充关键边界处理。"
    assert result["submission_status"]["status"] == "Unaccepted"


def test_numoj_admin_wait_promptly_review_result_treats_judge_failure_as_review_success():
    cli = _load_numoj_admin_cli_module()

    class FakeResponse:
        status_code = 200
        headers = {"Content-Type": "application/json"}
        text = ""
        reason = "OK"

        def json(self):
            return {
                "status": "Unaccepted",
                "prompt_generation_error": "",
                "promptly_review_reply": "",
            }

    class FakeClient:
        def request(self, method, path):
            assert method == "GET"
            assert path == "/submission_status/102"
            return FakeResponse()

    result = cli.wait_promptly_review_result(
        FakeClient(),
        102,
        timeout_seconds=1.0,
        poll_interval_seconds=0.1,
    )

    assert result["done"] is True
    assert result["accepted"] is True
    assert result["reply"] == ""
    assert result["status"] == "Unaccepted"


def test_promptly_task_does_not_regenerate_pending_submission(monkeypatch):
    import oj_modules.tasks.promptly_tasks as promptly_tasks

    monkeypatch.setattr(
        promptly_tasks,
        "get_submission_by_id",
        lambda sid: {"id": sid, "status": "Pending"},
    )
    monkeypatch.setattr(
        promptly_tasks,
        "review_promptly_student_prompt",
        lambda *args, **kwargs: pytest.fail("Pending 提交不应重新审查 prompt"),
    )

    task = promptly_tasks.register_promptly_generate_submission_task(_FakeCelery(), None)
    result = task(None, 103)

    assert result["success"] is False
    assert "Pending" in result["message"]


def test_promptly_task_keeps_pending_submission_when_evaluation_enqueue_fails(monkeypatch):
    import oj_modules.tasks.promptly_tasks as promptly_tasks

    generated_updates = []
    prompt_errors = []

    class FailingEvaluateTask:
        def __init__(self):
            self.calls = []

        def delay(self, submission_id):
            self.calls.append(submission_id)
            raise RuntimeError("broker down")

    evaluate_task = FailingEvaluateTask()

    monkeypatch.setattr(
        promptly_tasks,
        "get_submission_by_id",
        lambda sid: {
            "id": sid,
            "status": "Generating",
            "problem_id": 7,
            "problem_type": 1,
            "username": "alice",
            "prompt_text": "Use a monotonic deque and expired index handling.",
        },
    )
    monkeypatch.setattr(
        promptly_tasks,
        "get_problem",
        lambda pid: {
            "id": pid,
            "type": 1,
            "programming_grading_mode": 3,
            "programming_grading_model": "test-model",
        },
    )
    monkeypatch.setattr(promptly_tasks, "update_submission_status", lambda *args, **kwargs: None)
    monkeypatch.setattr(promptly_tasks, "set_submission_status_snapshot", lambda **kwargs: None)
    resolved_endpoints = {
        "review_endpoint_id": object(),
        "code_generation_endpoint_id": object(),
    }
    monkeypatch.setattr(
        promptly_tasks,
        "resolve_problem_llm_endpoint_snapshot",
        lambda _problem, binding_key: resolved_endpoints[binding_key],
    )
    monkeypatch.setattr(promptly_tasks, "review_promptly_student_prompt", lambda **kwargs: (True, ""))
    monkeypatch.setattr(promptly_tasks, "generate_promptly_code", lambda **kwargs: "print('hello')\n")
    monkeypatch.setattr(
        promptly_tasks,
        "update_submission_generated_code",
        lambda sid, code, status="Pending": generated_updates.append((sid, code, status)),
    )
    monkeypatch.setattr(
        promptly_tasks,
        "update_submission_prompt_generation_error",
        lambda *args, **kwargs: prompt_errors.append((args, kwargs)),
    )

    task = promptly_tasks.register_promptly_generate_submission_task(_FakeCelery(), evaluate_task)
    result = task(None, 104)

    assert result["success"] is False
    assert "入队失败" in result["message"]
    assert generated_updates == [(104, "print('hello')\n", "Pending")]
    assert evaluate_task.calls == [104]
    assert prompt_errors == []


def test_promptly_generation_uses_full_problem_after_review(monkeypatch):
    from oj_modules import ai_utils

    captured = {}

    def fake_call_llm_text(prompt_text, _endpoint, **kwargs):
        captured["prompt_text"] = prompt_text
        captured["system_prompt"] = kwargs.get("system_prompt")
        return "int main() { return 0; }"

    monkeypatch.delenv("NUMOJ_FAKE_PROMPTLY_CODE", raising=False)
    monkeypatch.setattr(ai_utils, "_call_llm_text", fake_call_llm_text)

    code = ai_utils.generate_promptly_code(
        problem={
            "title": "VISIBLE TITLE",
            "content": "VISIBLE PROBLEM CONTENT",
            "initial_code": "VISIBLE INITIAL CODE",
            "lang": "cpp",
            "programming_grading_prompt": _promptly_review_config(),
        },
        student_prompt="Use the algorithm I described.",
        endpoint=_text_endpoint(),
    )

    assert code == "int main() { return 0; }"
    assert "VISIBLE TITLE" in captured["prompt_text"]
    assert "VISIBLE PROBLEM CONTENT" in captured["prompt_text"]
    assert "VISIBLE INITIAL CODE" in captured["prompt_text"]
    assert "Use the algorithm I described." in captured["prompt_text"]
    assert "已经通过前置审查" in captured["system_prompt"]
