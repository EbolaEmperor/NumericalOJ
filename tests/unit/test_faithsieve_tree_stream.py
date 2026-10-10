"""真实 SSE 字节分片经过统一端点适配，再由 FaithSieve 完整校验树。"""

from copy import deepcopy
import json

import pytest
import requests

from backend.oj_modules.ai import endpoints as llm
from backend.oj_modules.faithsieve import prompts, workflow
from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.errors import FaithSieveEndpointError
from backend.oj_modules.faithsieve.proof_tree import expand_proof_tree_transport
from backend.oj_modules.faithsieve.transport import result_request_options
from tests.unit.test_faithsieve_transport import openai_endpoint
from tests.unit.test_faithsieve_workflow import thinking_endpoint, tree_payload


MODES = ("openai_function", "openai_json", "anthropic_function")
MAX_STREAM_BYTES = 8 * 1024 * 1024
RESULT_PATH = "faithsieve-work/results/tree-builder.json"


def endpoint(mode):
    return thinking_endpoint() if mode == "anthropic_function" else openai_endpoint(enabled=mode == "openai_function")


def tree_input():
    tree = tree_payload(2)
    root, first, last = tree["nodes"]
    condition = r"题面：$x\in\mathbb{R}$，$\frac{x}{2}\le x$"
    claim = "$$\n" + r"u(y)=\int_0^1 y(t)\,dt" + "\n$$"
    root.update(conditions=[condition], goal=r"完整目标：$\forall y,\ \nu(y)=\nu(y)$")
    first.update(conditions={"inherit_from": "N0", "remove": [], "add": [claim]},
                 goal={"inherit_from": "N0"}, scope=["原稿第 1 页的局部对象 y"])
    last.update(conditions={"inherit_from": "N1", "remove": [1], "add": []},
                goal={"inherit_from": "N0"}, scope=[])
    tree["edges"][0].update(source_text=claim, changes={"retained": [condition], "added": [claim], "consumed": [], "transformed": []},
                            scope=["原稿第 1 页的局部对象 y"])
    tree["edges"][1].update(source_text="退出局部证明，恢复原目标。", changes={"retained": [condition], "added": [], "consumed": [claim], "transformed": []}, scope=[])
    files = {"problem.md": "完整题面，保留定义、量词和目标。", workflow.STEPS:
             f"## S1\n{claim}\n\n## S2\n退出局部证明，恢复原目标。"}
    payload = {"result": {"status": "ok", "artifact": workflow.TREE, "report": "两步忠实状态及作用域。"},
               "artifacts": {workflow.TREE: tree}}
    return files, payload


def sse(event):
    return ("data: " + (event if isinstance(event, str) else json.dumps(event, ensure_ascii=False)) + "\n\n").encode("utf-8")


def stream_body(mode, payload, *, finish=None, terminal=True, text=""):
    arguments = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    pieces = [arguments[index:index + 19] for index in range(0, len(arguments), 19)]
    if mode.startswith("openai"):
        events = [{"model": "configured-model", "choices": [{"delta": {"reasoning_content": part}, "finish_reason": None}]}
                  for part in ("独立", "核对原稿与作用域")]
        if mode == "openai_json":
            events.extend({"choices": [{"delta": {"content": part}, "finish_reason": None}]} for part in pieces)
        else:
            events.append({"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "tree-result", "type": "function", "function": {"name": "faithsieve_", "arguments": ""}}]}}]})
            events.extend({"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"name": "result" if index == 0 else "", "arguments": part}}]}, "finish_reason": None}]}
                          for index, part in enumerate(pieces))
            if text:
                events.append({"choices": [{"delta": {"content": text}, "finish_reason": None}]})
        events.extend([{"choices": [{"delta": {}, "finish_reason": finish or ("stop" if mode == "openai_json" else "tool_calls")}]},
                       {"choices": [], "usage": {"prompt_tokens": 11, "completion_tokens": 23, "total_tokens": 34}}])
        return b"".join(map(sse, events)) + (sse("[DONE]") if terminal else b"")
    events = [{"type": "message_start", "message": {"model": "configured-model", "usage": {"input_tokens": 11, "output_tokens": 0}}},
              {"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": "独立"}},
              {"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "核对原稿与作用域"}},
              {"type": "content_block_stop", "index": 0},
              {"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": "tree-result", "name": "faithsieve_result", "input": {}}}]
    events.extend({"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": part}} for part in pieces)
    events.append({"type": "content_block_stop", "index": 1})
    if text:
        events.extend([{"type": "content_block_start", "index": 2, "content_block": {"type": "text", "text": ""}},
                       {"type": "content_block_delta", "index": 2, "delta": {"type": "text_delta", "text": text}},
                       {"type": "content_block_stop", "index": 2}])
    events.append({"type": "message_delta", "delta": {"stop_reason": finish or "tool_use"}, "usage": {"output_tokens": 23}})
    if terminal:
        events.append({"type": "message_stop"})
    return b"".join(map(sse, events))


class SSEBytesResponse:
    def __init__(self, body, *, observe=None, trap_tail=False, tail_error=None, content_type="text/event-stream"):
        self.body = body
        self.headers = {"Content-Type": content_type}
        self.status_code = 200
        self.observe = observe
        self.trap_tail = trap_tail
        self.tail_error = tail_error
        self.close_count = 0
        self.tail_reads = 0

    def iter_content(self, chunk_size=8192, decode_unicode=False):
        assert chunk_size <= 8192 and decode_unicode is False
        # 13 字节分片故意拆开 UTF-8 字符、JSON 转义对和 SSE 行。
        for offset in range(0, len(self.body), 13):
            if self.observe:
                self.observe()
            yield self.body[offset:offset + 13]
        if self.tail_error is not None:
            raise self.tail_error
        if self.trap_tail:
            self.tail_reads += 1
            pytest.fail("供应商完结标记后不得继续读取连接")

    def iter_lines(self, **_options):
        pytest.fail("严格有界流应读取字节分片，不能先接收完整无界行")

    def json(self):
        pytest.fail("严格流式请求不能回退为普通 JSON 响应")

    def close(self):
        self.close_count += 1


def no_published_tree(root):
    assert not (root / workflow.TREE).exists()
    assert not (root / RESULT_PATH).exists()
    assert not (root / workflow.RESULT).exists()
    records = list((root / "faithsieve-work/checkpoints").glob("*.json"))
    assert all(json.loads(path.read_text())["state"] != "completed" for path in records)


def invoke_engine(root, mode, response_factory):
    http_calls, replies, chat_results = [], [], []
    def post(_url, **options):
        http_calls.append({key: deepcopy(options[key]) for key in ("json", "stream", "timeout")})
        reply = response_factory()
        replies.append(reply)
        return reply
    def chat(model, messages, **options):
        result = llm.call_chat(model, messages, request_post=post, **options)
        chat_results.append(result)
        return result
    run = workflow.FaithSieveWorkflow(endpoint=endpoint(mode), verification_agent=None, workspace=root,
                                     chat=chat, initial_reasoning_effort="low")
    return run, http_calls, replies, chat_results


@pytest.mark.parametrize("mode", MODES)
def test_tree_byte_stream_completes_before_publish_expands_and_replays_without_http(tmp_path, mode):
    files, payload = tree_input()
    body = stream_body(mode, payload)
    run, calls, replies, results = invoke_engine(tmp_path, mode, lambda: SSEBytesResponse(body, observe=lambda: no_published_tree(tmp_path), trap_tail=True))
    output = run._invoke("tree-builder", files=files)
    assert len(calls) == 1 and replies[0].close_count >= 1 and replies[0].tail_reads == 0
    request = run.store.read_json("faithsieve-work/checkpoints/role-000001-attempt-1.json")["request"]
    options = request["call_options"]
    assert options["stream"] is True and options["require_complete_stream"] is True
    assert options["max_stream_bytes"] == MAX_STREAM_BYTES and options["timeout"] == 600
    assert calls[0]["stream"] is True and calls[0]["timeout"] == 600
    assert calls[0]["json"]["stream"] is True and calls[0]["json"]["max_tokens"] == 64000
    assert not {"require_complete_stream", "max_stream_bytes", "timeout"} & calls[0]["json"].keys()
    if mode.startswith("openai"):
        assert options["stream_options"] == calls[0]["json"]["stream_options"] == {"include_usage": True}
    else:
        assert "stream_options" not in options and "stream_options" not in calls[0]["json"]
    assert results[0].reasoning == "独立核对原稿与作用域"
    assert results[0].usage.input_tokens == 11 and results[0].usage.output_tokens == 23 and results[0].usage.total_tokens == 34
    assert results[0].finish_reason == ("tool_use" if mode == "anthropic_function" else "stop" if mode == "openai_json" else "tool_calls")
    assert run.store.read_json(workflow.TREE) == expand_proof_tree_transport(payload["artifacts"][workflow.TREE])
    assert output.control["edge_units"] == ["E1", "E2"]
    assert output.control["edge_contexts"]["E1"]["child_state"]["scope"] == ["原稿第 1 页的局部对象 y"]
    assert output.control["edge_contexts"]["E2"]["child_state"]["conditions"] == payload["artifacts"][workflow.TREE]["nodes"][0]["conditions"]
    if mode == "openai_json":
        assert json.loads(results[0].text) == payload
    else:
        assert results[0].text == "" and len(results[0].tool_calls) == 1
        assert json.loads(results[0].tool_calls[0].arguments) == payload
    path = run.checkpoints._path("role-000001-attempt-1")
    saved = path.read_bytes()
    replay, replay_calls, _, _ = invoke_engine(tmp_path, mode, lambda: pytest.fail("完整流已完成缓存不重调模型"))
    assert replay._invoke("tree-builder", files=files).result == output.result
    assert not replay_calls and path.read_bytes() == saved


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("failure", ["missing_terminal", "broken_connection", "invalid_frame", "non_sse"])
def test_incomplete_or_invalid_stream_is_single_safe_endpoint_failure_without_partial_outputs(tmp_path, mode, failure):
    files, payload = tree_input()
    body = stream_body(mode, payload, terminal=False)
    options = {"observe": lambda: no_published_tree(tmp_path)}
    if failure == "broken_connection":
        options["tail_error"] = requests.exceptions.ChunkedEncodingError("PRIVATE-PROVIDER-CONTENT")
    elif failure == "invalid_frame":
        body += b'data: {"PRIVATE-PROVIDER-CONTENT":broken}\n\n'
    elif failure == "non_sse":
        options["content_type"] = "application/json"
    run, calls, replies, _ = invoke_engine(tmp_path, mode, lambda: SSEBytesResponse(body, **options))
    for _reentry in range(2):
        if _reentry:
            run, replay_calls, _, _ = invoke_engine(tmp_path, mode, lambda: pytest.fail("失败流检查点不能重新发请求"))
        with pytest.raises(FaithSieveEndpointError) as raised:
            run._invoke("tree-builder", files=files)
        assert "PRIVATE-PROVIDER-CONTENT" not in str(raised.value)
    assert len(calls) == 1 and not replay_calls and replies[0].close_count >= 1
    no_published_tree(tmp_path)
    records = list((tmp_path / "faithsieve-work/checkpoints").glob("*.json"))
    assert len(records) == 1 and json.loads(records[0].read_text())["state"] == "endpoint_error"
    assert "PRIVATE-PROVIDER-CONTENT" not in records[0].read_text()


@pytest.mark.parametrize("mode", MODES)
def test_stream_total_byte_limit_includes_keepalives_after_complete_json(tmp_path, mode):
    files, payload = tree_input()
    body = stream_body(mode, payload, terminal=False)

    class OverBudgetResponse(SSEBytesResponse):
        def iter_content(self, chunk_size=8192, decode_unicode=False):
            assert chunk_size <= 8192 and decode_unicode is False
            self.wire_bytes = 0
            for offset in range(0, len(self.body), chunk_size):
                chunk = self.body[offset:offset + chunk_size]
                self.wire_bytes += len(chunk)
                yield chunk
            # 正文已完整到达仍未收到完结标记，心跳也必须计入相同字节上限。
            remaining = MAX_STREAM_BYTES - self.wire_bytes
            keepalive = b":\n" * (chunk_size // 2)
            for _ in range(remaining // chunk_size):
                self.wire_bytes += len(keepalive)
                yield keepalive
            padding = b" " * (remaining % chunk_size)
            self.wire_bytes += len(padding)
            yield padding
            no_published_tree(tmp_path)
            self.wire_bytes += 1
            yield b"x"
            pytest.fail("超出总字节上限后不得继续读取连接")

    run, calls, replies, results = invoke_engine(tmp_path, mode, lambda: OverBudgetResponse(body))
    with pytest.raises(FaithSieveEndpointError, match="模型端点返回的响应无效"):
        run._invoke("tree-builder", files=files)
    assert len(calls) == 1 and not results
    assert replies[0].wire_bytes == MAX_STREAM_BYTES + 1 and replies[0].close_count >= 1
    no_published_tree(tmp_path)
    record = run.store.read_json("faithsieve-work/checkpoints/role-000001-attempt-1.json")
    assert record["state"] == "endpoint_error"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("failure", ["invalid_tree", "truncated_finish"])
def test_completed_stream_still_obeys_strict_tree_and_original_two_protocol_attempts(tmp_path, mode, failure):
    files, payload = tree_input()
    if failure == "invalid_tree":
        payload["artifacts"][workflow.TREE]["nodes"][0]["goal"] = ""
    finish = ("max_tokens" if mode == "anthropic_function" else "length") if failure == "truncated_finish" else None
    body = stream_body(mode, payload, finish=finish)
    run, calls, replies, _ = invoke_engine(tmp_path, mode, lambda: SSEBytesResponse(body, observe=lambda: no_published_tree(tmp_path), trap_tail=True))
    with pytest.raises(FaithSieveProtocolError):
        run._invoke("tree-builder", files=files)
    assert len(calls) == 2 and all(reply.close_count >= 1 and reply.tail_reads == 0 for reply in replies)
    no_published_tree(tmp_path)
    records = list((tmp_path / "faithsieve-work/checkpoints").glob("*.json"))
    assert len(records) == 2 and all(json.loads(path.read_text())["state"] == "protocol_error" for path in records)


@pytest.mark.parametrize("mode", ("openai_function", "anthropic_function"))
def test_stream_can_aggregate_text_but_result_function_protocol_still_rejects_it(tmp_path, mode):
    files, payload = tree_input()
    body = stream_body(mode, payload, text="额外旁白")
    run, calls, _, results = invoke_engine(tmp_path, mode, lambda: SSEBytesResponse(body, trap_tail=True))
    with pytest.raises(FaithSieveProtocolError, match="正文或旁白"):
        run._invoke("tree-builder", files=files)
    assert len(calls) == 2 and all(result.text == "额外旁白" and result.reasoning == "独立核对原稿与作用域" for result in results)
    no_published_tree(tmp_path)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("old_format", ("raw_current", "raw_previous_tree", "json"))
@pytest.mark.parametrize("state", ("completed", "pending", "protocol_error", "endpoint_error"))
def test_non_stream_history_is_readonly_completed_compatibility_only(tmp_path, mode, old_format, state):
    files, payload = tree_input()
    run, calls, _, _ = invoke_engine(tmp_path, mode, lambda: pytest.fail("旧记录不能转换wire重新调用"))
    options = {**result_request_options(run.endpoint, fields={"status", "artifact", "report"},
                                       statuses={"ok", "needs_revision", "inconclusive"}, artifact=workflow.TREE),
               **run._initial_reasoning_options("tree-builder")}
    assert "stream" not in options
    system = prompts.model_result_prompt(prompts.render_role_prompt("tree-builder", legacy_input=old_format == "json",
                                         legacy_tree_transport=old_format == "raw_previous_tree"), options, tree=True, legacy_result=True)
    request = {"role": "tree-builder", "prompt": system, "files": files, "parameters": {}, "revision_report": "",
               "expected_result_path": RESULT_PATH, "endpoint": run._endpoint_identity(), "call_options": options}
    if old_format != "json":
        request["messages"] = [{"role": "system", "content": system},
                               {"role": "user", "content": prompts.input_message(files)}]
    full_tree = json.dumps(expand_proof_tree_transport(payload["artifacts"][workflow.TREE]), ensure_ascii=False, indent=2)
    saved_response = {**payload, "artifacts": {workflow.TREE: full_tree}, "control": {}, "execution": {}}
    key = "role-000001-attempt-1"
    run.checkpoints.put(key, request, state=state, response=saved_response)
    path = run.checkpoints._path(key)
    saved = path.read_bytes()
    if state == "completed":
        assert run._invoke("tree-builder", files=files).control["edge_units"] == ["E1", "E2"]
    else:
        with pytest.raises(FaithSieveProtocolError, match="完整输入不一致"):
            run._invoke("tree-builder", files=files)
    assert not calls and path.read_bytes() == saved
