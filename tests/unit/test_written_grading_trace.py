"""完整传输、逐轮隔离、失败留痕和管理员读取权限；不访问模型或数据库。"""

import io
import json

from flask import Flask
import pytest
import requests
from celery.exceptions import SoftTimeLimitExceeded

from backend.oj_modules.ai import endpoints, grading
from backend.oj_modules.submissions import written_trace as traces
from backend.oj_modules.tasks import written_homework_tasks as tasks


@pytest.fixture(autouse=True)
def private_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(traces, "TRACE_ROOT", tmp_path / "traces")
    monkeypatch.setattr(tasks, "update_vote", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tasks, "finish_attempt", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tasks.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(grading.time, "sleep", lambda _seconds: None)


def endpoint(protocol="openai", model="judge"):
    return endpoints.LLMEndpointSnapshot(
        id=13, category="omni", protocol=protocol, model=model,
        base_url="https://model.example.test", api_key="secret-header-canary",
        thinking_format="none",
    )


def vote(snapshot=None, index=3):
    return {
        "id": index, "vote_index": index, "endpoint_id": 13, "endpoint_revision": 3,
        "model": f"judge-{index}", "endpoint": snapshot or endpoint(),
    }


def http_response(payload, body, status=200, content_type="application/json"):
    response = requests.Response()
    response.status_code = status
    response.headers["Content-Type"] = content_type
    response.raw = io.BytesIO(body)
    response.encoding = "utf-8"
    response.request = requests.Request(
        "POST", "https://model.example.test", json=payload,
        headers={"Authorization": "Bearer secret-header-canary"},
    ).prepare()
    return response


def body_for(protocol, text, *, streaming=False):
    if protocol == "openai":
        if streaming:
            events = [
                {"choices": [{"delta": {"reasoning_content": "完整思考"}}]},
                {"choices": [{"delta": {"content": text}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 11, "completion_tokens": 12}},
            ]
            return ("".join("data: " + json.dumps(item, ensure_ascii=False) + "\r\n\r\n" for item in events) + "data: [DONE]\r\n\r\n").encode()
        return json.dumps({"choices": [{"message": {"content": text}, "finish_reason": "stop"}]}, ensure_ascii=False).encode()
    if streaming:
        events = [
            {"type": "message_start", "message": {"model": "judge-3", "usage": {"input_tokens": 11}}},
            {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}},
            {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 12}},
            {"type": "message_stop"},
        ]
        return "".join("data: " + json.dumps(item, ensure_ascii=False) + "\n\n" for item in events).encode()
    return json.dumps({"content": [{"type": "text", "text": text}], "stop_reason": "end_turn"}, ensure_ascii=False).encode()


@pytest.mark.parametrize("protocol", ["openai", "anthropic"])
def test_three_rounds_keep_actual_requests_and_full_streams(protocol, tmp_path, monkeypatch):
    image_path = tmp_path / "answer.png"
    image_path.write_bytes(b"complete-original-image")
    sent = {}

    def post(_url, **kwargs):
        payload = kwargs["json"]
        index = int(payload["model"].split("-")[-1])
        number = (len(payload["messages"]) + 1) // 2
        result = {"score": 5 if index == 3 else 4, "deductions": [], "comment": f"评委{index}第{number}轮总评"}
        if number > 1:
            result["peer_replies"] = [{"vote_index": other, "reply": f"{index}回复{other}：第{number}轮"} for other in (1, 2, 3) if other != index]
        raw = body_for(protocol, json.dumps(result, ensure_ascii=False), streaming=True)
        response = http_response(payload, raw, content_type="text/event-stream")
        sent[index, number] = (response.request.body, raw)
        return response

    monkeypatch.setattr(endpoints.requests, "post", post)
    plan = [vote(endpoint(protocol, f"judge-{index}"), index) for index in (1, 2, 3)]
    score, message = tasks._evaluate_written_votes(
        {"id": 384, "submission_id": 46323}, plan,
        lambda snapshot, index: grading.evaluate_written_homework_with_ai_from_images(
            {"title": "作业", "content": "完整题面", "written_grading_prompt": "教师私有规则"},
            [str(image_path)], endpoint=snapshot, return_round=True, vote_index=index,
        ),
        lambda snapshot, previous, peers, number: grading.reconsider_written_homework_with_ai(
            previous, peers, endpoint=snapshot, round_number=number,
        ),
    )
    assert score is None
    assert "第三轮" in message
    records = traces.list_submission_traces(46323)
    assert len(records) == 9
    for record in records:
        index, number = record["vote_index"], record["round_number"]
        assert record["status"] == "completed"
        assert len(record["calls"]) == 1
        call = record["calls"][0]
        assert call["status"] == "received" and call["body_complete"]
        with traces.open_trace_artifact(46323, record["record_id"], call["request_file"]) as stream:
            request_body = stream.read()
        with traces.open_trace_artifact(46323, record["record_id"], call["response_file"]) as stream:
            response_body = stream.read()
        assert (request_body, response_body) == sent[index, number]
        payload = json.loads(request_body)
        assert len(payload["messages"]) == 2 * number - 1
        assert b"secret-header-canary" not in request_body + response_body
        assert "教师私有规则" in request_body.decode("unicode_escape")
        if number > 1:
            assert len(record["result"]["peer_replies"]) == 2
        if number == 3 and index == 3:
            assert "1回复3：第2轮" in json.dumps(payload, ensure_ascii=False)
            assert "2回复3：第2轮" in json.dumps(payload, ensure_ascii=False)
            assert record["result"]["comment"] == "AI 自动评分：5/5\n\n评语：评委3第3轮总评"
    for path in traces.TRACE_ROOT.rglob("*"):
        assert path.stat().st_mode & 0o077 == 0


def test_json_repair_keeps_original_response_and_separate_exchange(monkeypatch):
    original = "模型原始损坏 JSON"
    repaired = '{"score":4,"deductions":["扣分"],"comment":"修复后"}'
    bodies = []

    def post(_url, **kwargs):
        text = original if not bodies else ("第一次修复仍损坏" if len(bodies) == 1 else repaired)
        body = body_for("openai", text)
        bodies.append(body)
        return http_response(kwargs["json"], body)

    monkeypatch.setattr(endpoints.requests, "post", post)
    trace = traces.WrittenVoteTrace(1, 2, vote(), 1, 1)
    with trace.capture():
        result = grading.evaluate_written_homework_with_ai(
            {"title": "作业"}, "学生完整答案", endpoint=endpoint(), return_round=True, vote_index=3,
        )
        trace.completed(result)
    record = traces.list_submission_traces(1)[0]
    assert [call["purpose"] for call in record["calls"]] == ["grading", "json_repair", "json_repair"]
    assert record["result"]["raw_response"] == repaired
    for call, body in zip(record["calls"], bodies):
        assert (trace.directory / call["response_file"]).read_bytes() == body


def test_failed_retries_never_overwrite_previous_call(monkeypatch):
    count = 0

    def post(_url, **kwargs):
        nonlocal count
        count += 1
        if count == 1:
            return http_response(kwargs["json"], b'{"error":"full provider error"}', status=503)
        return http_response(kwargs["json"], body_for("openai", '{"score":4,"comment":"成功"}'))

    monkeypatch.setattr(endpoints.requests, "post", post)
    result = tasks._run_written_vote(
        2, vote(), lambda snapshot: grading.evaluate_written_homework_with_ai(
            {}, "答案", endpoint=snapshot, return_round=True,
        ), submission_id=1, round_number=2,
    )
    assert result["score"] == 4
    first, second = traces.list_submission_traces(1)
    assert (first["call_attempt"], second["call_attempt"]) == (1, 2)
    assert first["status"] == "failed" and second["status"] == "completed"
    assert first["calls"][0]["http_status"] == 503
    assert (traces.TRACE_ROOT / "1" / first["record_id"] / "call-1.response.body").read_bytes() == b'{"error":"full provider error"}'


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("failure", [requests.ConnectionError, SoftTimeLimitExceeded])
def test_partial_response_survives_disconnect(monkeypatch, streaming, failure):
    prefix = b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n'

    class BrokenBody:
        def stream(self, *_args, **_kwargs):
            yield prefix
            raise failure("secret-header-canary should not enter metadata")
        def close(self): pass
        def release_conn(self): pass

    def post(_url, **kwargs):
        response = http_response(kwargs["json"], b"", content_type="text/event-stream" if streaming else "application/json")
        response.raw = BrokenBody()
        return response

    monkeypatch.setattr(endpoints.requests, "post", post)
    trace = traces.WrittenVoteTrace(1, 2, vote(), 2, 1)
    error_type = failure if streaming or failure is SoftTimeLimitExceeded else endpoints.LLMEndpointResponseError
    with pytest.raises(error_type), trace.capture():
        endpoints.call_text(endpoint(), "完整提示词", stream=streaming)
    record = traces.list_submission_traces(1)[0]
    assert record["status"] == "failed"
    assert record["calls"][0]["error_type"] == failure.__name__
    assert not record["calls"][0]["body_complete"]
    assert (trace.directory / "call-1.response.body").read_bytes() == prefix
    assert "secret-header-canary" not in (trace.directory / "round.json").read_text()


def test_connection_failure_is_recorded_before_receiving_headers(monkeypatch):
    def post(*_args, **_kwargs):
        raise requests.Timeout("private request details")
    monkeypatch.setattr(endpoints.requests, "post", post)
    trace = traces.WrittenVoteTrace(1, 2, vote(), 1, 1)
    with pytest.raises(endpoints.LLMEndpointRequestError), trace.capture():
        endpoints.call_text(endpoint(), "完整提示词")
    record = traces.list_submission_traces(1)[0]
    assert record["calls"][0]["error_type"] == "timeout"
    assert (trace.directory / "call-1.request.json").exists()
    assert (trace.directory / "call-1.response.body").read_bytes() == b""


def test_soft_time_limit_keeps_round_and_does_not_leak_recorder(monkeypatch):
    def post(*_args, **_kwargs):
        raise SoftTimeLimitExceeded()
    monkeypatch.setattr(endpoints.requests, "post", post)
    with pytest.raises(SoftTimeLimitExceeded):
        tasks._run_written_vote(
            2, vote(), lambda snapshot: endpoints.call_text(snapshot, "题面"), submission_id=1,
        )
    record = traces.list_submission_traces(1)[0]
    assert record["status"] == "failed"
    assert record["error_type"] == "SoftTimeLimitExceeded"
    from backend.oj_modules.ai.exchange_capture import begin_exchange
    assert begin_exchange({"not": "recorded"}) is None


def test_invalid_json_response_keeps_exact_body(monkeypatch):
    raw = b'not JSON\xff\x00\r\n'
    monkeypatch.setattr(endpoints.requests, "post", lambda _url, **kwargs: http_response(kwargs["json"], raw))
    trace = traces.WrittenVoteTrace(1, 2, vote(), 1, 1)
    with pytest.raises(endpoints.LLMEndpointResponseError), trace.capture():
        endpoints.call_text(endpoint(), "题面")
    assert (trace.directory / "call-1.response.body").read_bytes() == raw
    record = traces.list_submission_traces(1)[0]
    assert record["status"] == "failed" and record["calls"][0]["body_complete"]


def test_storage_failure_blocks_model_call(tmp_path, monkeypatch):
    traces.TRACE_ROOT.write_text("not a directory")
    monkeypatch.setattr(endpoints.requests, "post", lambda *_a, **_k: pytest.fail("不应发起模型调用"))
    result = tasks._run_written_vote(2, vote(), lambda snapshot: endpoints.call_text(snapshot, "题面"), submission_id=1)
    assert "error" in result


@pytest.mark.parametrize("user,status", [(None, 401), ({"is_admin": 0}, 403)])
def test_trace_apis_reject_non_admin_before_loading_data(monkeypatch, user, status):
    from backend.oj_modules.api import submission_api as api
    monkeypatch.setattr(api, "current_user", lambda: user)
    monkeypatch.setattr(api, "get_submission_by_id", lambda _sid: pytest.fail("鉴权失败不能查提交"))
    app = Flask(__name__)
    app.register_blueprint(api.submission_api_bp)
    for suffix in ("", "/" + "a" * 32 + "/round.json"):
        response = app.test_client().get("/api/admin/submissions/1/grading-trace" + suffix)
        assert response.status_code == status


def test_admin_can_read_full_artifact_without_exposing_it_in_public_payload(monkeypatch):
    from backend.oj_modules.api import submission_api as api
    from backend.oj_modules.submissions.written_voting import public_attempt_payload
    monkeypatch.setattr(api, "current_user", lambda: {"is_admin": 1})
    monkeypatch.setattr(api, "get_submission_by_id", lambda sid: {"id": sid, "problem_type": 2})
    trace = traces.WrittenVoteTrace(1, 2, vote(), 3, 1)
    with trace.capture():
        trace.completed(grading.WrittenGradingRound(5, "最后总评", "讨论 JSON", "私有教师提示词", peer_replies=({"vote_index": 1, "reply": "具体讨论"},)))
    app = Flask(__name__)
    app.register_blueprint(api.submission_api_bp)
    client = app.test_client()
    response = client.get("/api/admin/submissions/1/grading-trace")
    assert response.headers["Cache-Control"] == "private, no-store"
    record = response.json["records"][0]
    assert record["result"]["peer_replies"][0]["reply"] == "具体讨论"
    downloaded = client.get(f"/api/admin/submissions/1/grading-trace/{trace.record_id}/round.json")
    assert downloaded.headers["Cache-Control"] == "private, no-store"
    assert downloaded.headers["X-Content-Type-Options"] == "nosniff"
    assert json.loads(downloaded.data)["result"]["raw_response"] == "讨论 JSON"
    public = public_attempt_payload({"id": 2, "votes": [{"vote_index": 3, "comment": "最后总评", "trace": record}]})
    assert "具体讨论" not in json.dumps(public, ensure_ascii=False)


def test_artifact_paths_reject_traversal_cross_submission_and_symlinks(tmp_path):
    trace = traces.WrittenVoteTrace(1, 2, vote(), 1, 1)
    for record_id, filename in [("../outside", "round.json"), (trace.record_id, "../round.json")]:
        with pytest.raises(ValueError):
            traces.open_trace_artifact(1, record_id, filename)
    with pytest.raises(FileNotFoundError):
        traces.open_trace_artifact(2, trace.record_id, "round.json")
    external = tmp_path / "outside"
    external.write_text("private")
    (trace.directory / "call-1.response.body").symlink_to(external)
    with pytest.raises(OSError):
        traces.open_trace_artifact(1, trace.record_id, "call-1.response.body")
