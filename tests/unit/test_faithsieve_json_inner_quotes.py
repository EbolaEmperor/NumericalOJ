"""保守修复对象字符串值中的括号内引号，数学内容与冻结历史必须保持。"""

import copy
import json

import pytest

from backend.oj_modules.ai.endpoints import LLMChatResult, LLMToolCall
from backend.oj_modules.faithsieve import json_repair, workflow
from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.json_repair import (
    REPAIR_SYSTEM_PROMPT, assert_repair_content_unchanged, content_tokens,
)
from backend.oj_modules.faithsieve.workflow import TREE, WORK
from tests.unit.test_faithsieve_image_repair import checkpoint_bytes
from tests.unit.test_faithsieve_image_workflow import Pending, Script, seed


REPORT = r'保持作者命题，target_ids=["N24"]。常数 C=7，阈值含 (\ln M)^5；尚未替作者补证。'


def malformed_report(payload):
    """最小复现真实故障的三处转义错误，无原稿转录或运行记录依赖。"""
    canonical = json.dumps(payload, ensure_ascii=False)
    assert r'\"N24\"' in canonical and r'\\ln' in canonical
    return canonical.replace(r'\"N24\"', '"N24"', 1).replace(r'\\ln', r'\ln', 1)


def minimal_payload():
    return {"result": {"status": "ok", "report": REPORT}, "artifacts": {"tree.json": {
        "nodes": [{"id": "N24", "statement": "常数 C=7，目标的量词和条件保持。"}],
        "target_ids": ["N24"], "value": 7}}}


def test_actual_failure_shape_preserves_inline_quoted_id_and_illegal_latex_escape_literally():
    payload = minimal_payload()
    raw, canonical = malformed_report(payload), json.dumps(payload, ensure_ascii=False)
    with pytest.raises(json.JSONDecodeError):
        json.loads(raw)
    assert content_tokens(raw) == content_tokens(canonical)
    assert_repair_content_unchanged(raw, canonical)
    strings = [token[1] for token in content_tokens(raw) if token[0] == "string"]
    assert REPORT in strings
    assert json.loads(canonical)["result"]["report"] == REPORT


@pytest.mark.parametrize("prefix,suffix", [("target_ids=", "。"), ("引用 ", " 仍保持。"),
                                          ("(集合=", ") 条件保持。")])
def test_bracketed_quoted_text_in_object_string_value_is_preserved(prefix, suffix):
    value = prefix + '["N24"]' + suffix
    canonical = json.dumps({"result": {"report": value}}, ensure_ascii=False)
    raw = canonical.replace(r'\"N24\"', '"N24"')
    assert_repair_content_unchanged(raw, canonical)
    assert content_tokens(raw) == content_tokens(canonical)


def test_multiple_bracketed_groups_empty_atoms_and_unicode_remain_literal_text():
    value = '已知 ["N24", ""]，目标 ["N25", "条件甲"]，不删除正文。'
    canonical = json.dumps({"result": {"report": value}}, ensure_ascii=False)
    raw = canonical.replace(r'\"', '"')
    assert_repair_content_unchanged(raw, canonical)
    assert content_tokens(raw) == content_tokens(canonical)


@pytest.mark.parametrize("atom,kind", [("24", "number"), ("true", "true"),
                                       ("false", "false"), ("null", "null")])
def test_existing_lexer_tokens_are_not_reinterpreted_as_one_literal_string(atom, kind):
    raw = '{"report":"target_ids=["' + atom + '"]"}'
    assert content_tokens(raw) == [
        ("container", "{", ()), ("string", "report", (0,)),
        ("string", "target_ids=[", (0,)), (kind, atom, (0,)), ("string", "]", (0,)),
    ]
    canonical = json.dumps({"report": 'target_ids=["' + atom + '"]'})
    with pytest.raises(FaithSieveProtocolError):
        assert_repair_content_unchanged(raw, canonical)


@pytest.mark.parametrize("quoted_list", ['["N24", 7]', '["N24", true]', '["N24", null]',
                                       '["N24", {"x":1}]', '["N24",]', '["N24", unknown]'])
def test_fallback_does_not_guess_mixed_or_incomplete_inline_quoted_lists(quoted_list):
    with pytest.raises(FaithSieveProtocolError):
        content_tokens('{"report":"target_ids=' + quoted_list + '，保持。"}')


def test_fallback_does_not_expand_to_strings_inside_array_or_root_string():
    for raw in ['["target_ids=["N24"]"]', '"target_ids=["N24"]"']:
        with pytest.raises(FaithSieveProtocolError):
            content_tokens(raw)


def test_fallback_cannot_bypass_the_existing_response_boundary_or_unicode_validation(monkeypatch):
    raw = malformed_report(minimal_payload())
    with monkeypatch.context() as context:
        context.setattr(json_repair, "MAX_RESPONSE_BYTES", len(raw.encode("utf-8")) - 1)
        with pytest.raises(FaithSieveProtocolError, match="原文过大"):
            content_tokens(raw)
    with pytest.raises(FaithSieveProtocolError, match="有效 Unicode"):
        content_tokens(raw.replace("保持作者命题", "\ud800"))
    with pytest.raises(FaithSieveProtocolError, match="歧义 Unicode"):
        content_tokens(raw.replace("保持作者命题", r"\uD800"))


@pytest.mark.parametrize("change", ["quoted_id", "latex", "constant", "status", "goal", "numeric_value",
                                    "field_name", "removed_leaf", "added_leaf", "container", "parent"])
def test_format_repair_cannot_change_ids_formulas_verdict_constants_fields_or_parent_ownership(change):
    original = minimal_payload()
    raw = malformed_report(original)
    altered = copy.deepcopy(original)
    if change == "quoted_id":
        altered["result"]["report"] = REPORT.replace('"N24"', '"N25"')
    elif change == "latex":
        altered["result"]["report"] = REPORT.replace(r'\ln', r'\log')
    elif change == "constant":
        altered["result"]["report"] = REPORT.replace("C=7", "C=8")
    elif change == "status":
        altered["result"]["status"] = "inconclusive"
    elif change == "goal":
        altered["artifacts"]["tree.json"]["nodes"][0]["statement"] = "常数 C=7，目标已成立。"
    elif change == "numeric_value":
        altered["artifacts"]["tree.json"]["value"] = 8
    elif change == "field_name":
        altered["result"]["summary"] = altered["result"].pop("report")
    elif change == "removed_leaf":
        altered["result"].pop("report")
    elif change == "added_leaf":
        altered["result"]["verdict"] = "correct"
    elif change == "container":
        altered["artifacts"]["tree.json"]["nodes"] = altered["artifacts"]["tree.json"]["nodes"][0]
    else:
        altered["result"]["tree.json"] = altered["artifacts"].pop("tree.json")
    with pytest.raises(FaithSieveProtocolError):
        assert_repair_content_unchanged(raw, json.dumps(altered, ensure_ascii=False))


@pytest.mark.parametrize("raw", [
    '{"report":unknown}',
    '{"report":"target_ids=["N24"]", "status": unknown}',
    '{"report":"target_ids=["N24"]"} unexplained',
    '{"report":"target_ids=["N24"]"}{"extra":1}',
    '{"report":"target_ids=["N24"]"}[1]',
    '{"key["N24"]":"普通值"}',
    '{"report":"target_ids=["N24]"}',
    '{"report":"target_ids=["N24"]，未闭合}',
    '{"report":"target_ids=["N24"]", "数学"裸词"}',
    '{"report":"target_ids=["N24"]", "status":"未闭合}',
    '{"report":"target_ids=["N24"]" "status": unexpected}',
])
def test_inner_quote_support_never_accepts_barewords_keys_unclosed_or_multiple_roots(raw):
    with pytest.raises(FaithSieveProtocolError):
        content_tokens(raw)


def test_repair_cannot_swallow_following_field_into_the_report():
    original = minimal_payload()
    raw = malformed_report(original)
    altered = copy.deepcopy(original)
    altered["result"]["report"] += ', "status": "ok"'
    altered["result"].pop("status")
    with pytest.raises(FaithSieveProtocolError):
        assert_repair_content_unchanged(raw, json.dumps(altered, ensure_ascii=False))


@pytest.mark.parametrize("original,repaired", [
    ('{"a":"x" "b":1}', '{"a":"x","b":1}'),
    ('{"a":{"x":1}},"b":[2]}', '{"a":{"x":1},"b":[2]}'),
    ('{"a":{"x":1,},"b":[2,],}', '{"a":{"x":1},"b":[2]}'),
    ('{"a":"","b":["普通数学条件",7,true,null]}', '{"a":"","b":["普通数学条件",7,true,null]}'),
])
def test_legacy_tokens_and_existing_format_only_repairs_are_unchanged(original, repaired):
    assert_repair_content_unchanged(original, repaired)


class InnerQuoteScript(Script):
    def __init__(self, root, *, failure=None):
        super().__init__(root)
        self.failure = failure
        self.repairs = []
        self.payload = None
        self.raw = None
        self.was_pending = False

    def chat(self, endpoint, messages, **options):
        if messages[0]["content"] == REPAIR_SYSTEM_PROMPT:
            self.repairs.append((endpoint, copy.deepcopy(messages), copy.deepcopy(options)))
            if self.failure == "pending" and not self.was_pending:
                self.was_pending = True
                raise Pending("json-repair")
            payload = copy.deepcopy(self.payload)
            if self.failure == "changed_content":
                payload["result"]["report"] = REPORT.replace("C=7", "C=8")
            if "response_format" in options:
                return LLMChatResult(text=json.dumps(payload, ensure_ascii=False), finish_reason="stop")
            return LLMChatResult(text="", finish_reason="tool_calls", tool_calls=(
                LLMToolCall(id="result", name="faithsieve_result", arguments=json.dumps(payload, ensure_ascii=False)),))
        reply = super().chat(endpoint, messages, **options)
        if messages[0]["content"].startswith("# Tree builder"):
            self.payload = json.loads(reply.tool_calls[0].arguments if reply.tool_calls else reply.text)
            self.payload["result"]["report"] = REPORT
            self.raw = malformed_report(self.payload)
            if "response_format" in options:
                return LLMChatResult(text=self.raw, finish_reason="stop")
            return LLMChatResult(text="", finish_reason="tool_calls", tool_calls=(
                LLMToolCall(id="result", name="faithsieve_result", arguments=self.raw),))
        return reply


@pytest.mark.parametrize("thinking", [False, True])
def test_complete_inner_quotes_use_one_isolated_llm_format_repair_and_readonly_completed_reentry(tmp_path, thinking):
    script = InnerQuoteScript(tmp_path)
    engine = seed(tmp_path, script, thinking=thinking)
    result = engine.run()
    assert result["verdict"] == "correct"
    assert [role for role, _messages, _options in script.pure].count("tree-builder") == len(script.repairs) == 1
    assert len(script.native) == 3
    original = engine.checkpoints.records()["role-000001-attempt-1"]
    repair = original["metadata"]["json_repair"]
    assert original["state"] == repair["state"] == "completed"
    assert original["response"]["result"]["report"] == REPORT
    assert repair["raw_response"] == script.raw
    _endpoint, messages, options = script.repairs[0]
    assert messages == repair["request"]["messages"] and script.raw in messages[1]["content"]
    assert all(type(message["content"]) is str for message in messages)
    assert "固定共享对象 x，给定命题1" not in messages[1]["content"]
    assert "pages.json" not in messages[1]["content"] and "data:image" not in messages[1]["content"]
    assert not {"max_tokens", "max_output_tokens", "max_stream_bytes"} & options.keys()
    assert not engine.checkpoints._path("role-000001-attempt-2").exists()
    assert not (engine.store.root / WORK / "source").exists()
    assert not (engine.store.root / WORK / "steps.md").exists()
    before, calls = checkpoint_bytes(engine), (len(script.pure), len(script.native), len(script.repairs))
    assert seed(tmp_path, script, thinking=thinking).run() == result
    assert checkpoint_bytes(engine) == before
    assert (len(script.pure), len(script.native), len(script.repairs)) == calls


def test_pending_inner_quote_repair_resumes_same_request_without_repeating_graph_generation(tmp_path):
    script = InnerQuoteScript(tmp_path, failure="pending")
    engine = seed(tmp_path, script, thinking=True)
    with pytest.raises(Pending):
        engine.run()
    pending = engine.checkpoints.records()["role-000001-attempt-1"]
    assert pending["metadata"]["json_repair"]["state"] == "pending"
    assert len(script.pure) == len(script.repairs) == 1 and not script.native
    assert seed(tmp_path, script, thinking=True).run()["verdict"] == "correct"
    assert script.repairs[0] == script.repairs[1]
    assert [role for role, _messages, _options in script.pure].count("tree-builder") == 1
    assert len(script.repairs) == 2 and len(script.native) == 3
    completed = engine.checkpoints.records()["role-000001-attempt-1"]
    assert completed["request"] == pending["request"]
    assert completed["metadata"]["json_repair"]["request"] == pending["metadata"]["json_repair"]["request"]


def test_inner_quote_repair_that_changes_mathematics_is_terminal_without_new_generation(tmp_path):
    script = InnerQuoteScript(tmp_path, failure="changed_content")
    engine = seed(tmp_path, script, thinking=True)
    assert engine.run()["verdict"] == "inconclusive"
    assert len(script.pure) == len(script.repairs) == 1 and not script.native
    record = engine.checkpoints.records()["role-000001-attempt-1"]
    assert record["state"] == record["metadata"]["json_repair"]["state"] == "protocol_error"
    assert not engine.store.path(TREE).exists()
    before, calls = checkpoint_bytes(engine), (len(script.pure), len(script.repairs))
    assert seed(tmp_path, script, thinking=True).run()["verdict"] == "inconclusive"
    assert checkpoint_bytes(engine) == before and (len(script.pure), len(script.repairs)) == calls


def test_historical_failed_quote_guard_is_not_republished_after_parser_support_changes(tmp_path, monkeypatch):
    script = InnerQuoteScript(tmp_path)
    engine = seed(tmp_path, script, thinking=True)

    def old_guard(_raw):
        raise FaithSieveProtocolError("JSON 格式修复原文含未知裸词或歧义引号")

    with monkeypatch.context() as context:
        context.setattr(workflow, "content_tokens", old_guard)
        assert engine.run()["verdict"] == "inconclusive"
    assert len(script.pure) == 1 and not script.repairs and not script.native
    record = engine.checkpoints.records()["role-000001-attempt-1"]
    assert record["state"] == record["metadata"]["json_repair"]["state"] == "protocol_error"
    assert record["metadata"]["json_repair"]["raw_response"] == script.raw
    before = checkpoint_bytes(engine)
    assert seed(tmp_path, script, thinking=True).run()["verdict"] == "inconclusive"
    assert checkpoint_bytes(engine) == before
    assert len(script.pure) == 1 and not script.repairs and not script.native
