# -*- coding: utf-8 -*-

import json


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


def test_review_promptly_student_prompt_accepts_nice(monkeypatch):
    from oj_modules import ai_utils

    captured = {}

    def fake_call_qwen_text(prompt_text, **kwargs):
        captured["prompt_text"] = prompt_text
        captured["system_prompt"] = kwargs.get("system_prompt")
        return '{"nice": true}'

    monkeypatch.setattr(ai_utils, "_call_qwen_text", fake_call_qwen_text)

    nice, reply = ai_utils.review_promptly_student_prompt(
        problem={"programming_grading_prompt": _promptly_review_config()},
        student_prompt="用两个单调队列维护最大最小值。",
        model_spec="test-model",
    )

    assert nice is True
    assert reply == ""
    assert "给定 n、k 和数组" in captured["system_prompt"]
    assert "需要说明单调队列" in captured["system_prompt"]
    assert "请补充具体算法思路" in captured["system_prompt"]
    assert "用两个单调队列维护最大最小值" in captured["prompt_text"]


def test_review_promptly_student_prompt_rejects_with_reply(monkeypatch):
    from oj_modules import ai_utils

    def fake_call_qwen_text(prompt_text, **kwargs):
        return '{"nice": false, "reply": "请说明具体使用的数据结构和更新规则。"}'

    monkeypatch.setattr(ai_utils, "_call_qwen_text", fake_call_qwen_text)

    nice, reply = ai_utils.review_promptly_student_prompt(
        problem={"programming_grading_prompt": _promptly_review_config()},
        student_prompt="帮我写 O(n) 算法。",
        model_spec="test-model",
    )

    assert nice is False
    assert reply == "请说明具体使用的数据结构和更新规则。"


def test_promptly_generation_uses_full_problem_after_review(monkeypatch):
    from oj_modules import ai_utils

    captured = {}

    def fake_call_qwen_text(prompt_text, **kwargs):
        captured["prompt_text"] = prompt_text
        captured["system_prompt"] = kwargs.get("system_prompt")
        return "int main() { return 0; }"

    monkeypatch.delenv("NUMOJ_FAKE_PROMPTLY_CODE", raising=False)
    monkeypatch.setattr(ai_utils, "_call_qwen_text", fake_call_qwen_text)

    code = ai_utils.generate_promptly_code(
        problem={
            "title": "VISIBLE TITLE",
            "content": "VISIBLE PROBLEM CONTENT",
            "initial_code": "VISIBLE INITIAL CODE",
            "lang": "cpp",
            "programming_grading_prompt": _promptly_review_config(),
        },
        student_prompt="Use the algorithm I described.",
        model_spec="test-model",
    )

    assert code == "int main() { return 0; }"
    assert "VISIBLE TITLE" in captured["prompt_text"]
    assert "VISIBLE PROBLEM CONTENT" in captured["prompt_text"]
    assert "VISIBLE INITIAL CODE" in captured["prompt_text"]
    assert "Use the algorithm I described." in captured["prompt_text"]
    assert "已经通过前置审查" in captured["system_prompt"]
