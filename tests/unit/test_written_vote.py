# -*- coding: utf-8 -*-

import pytest

from backend.oj_modules.ai.grading import WrittenGradingJSONRepairError, WrittenGradingRound
from backend.oj_modules.problems.written_vote import (
    WrittenVoteConfigError,
    deserialize_written_vote_config,
    normalize_written_vote_config,
    serialize_written_vote_config,
)
from backend.oj_modules.tasks import written_homework_tasks as tasks
from backend.oj_modules.submissions.written_voting import public_attempt_payload


@pytest.fixture(autouse=True)
def skip_vote_retry_waits(monkeypatch):
    monkeypatch.setattr(tasks.time, "sleep", lambda _seconds: None)


def test_written_vote_config_round_trip():
    config = [
        {"endpoint_id": 11, "count": 2},
        {"endpoint_id": 12, "count": 1},
    ]
    assert deserialize_written_vote_config(serialize_written_vote_config(config)) == config


def test_written_vote_config_rejects_duplicate_endpoint_and_excess_total():
    with pytest.raises(WrittenVoteConfigError, match="只能配置一行"):
        normalize_written_vote_config([
            {"endpoint_id": 11, "count": 1},
            {"endpoint_id": 11, "count": 2},
        ])

    with pytest.raises(WrittenVoteConfigError, match="总次数"):
        normalize_written_vote_config([
            {"endpoint_id": 11, "count": 5},
            {"endpoint_id": 12, "count": 5},
            {"endpoint_id": 13, "count": 1},
        ])


def test_public_vote_payload_keeps_comments_and_manual_override():
    payload = public_attempt_payload({
        "id": 8,
        "status": "needs_manual_review",
        "consensus_score": None,
        "manual_override": 1,
        "manual_score": 4,
        "votes": [{
            "vote_index": 1,
            "endpoint_id": 99,
            "endpoint_revision": 7,
            "model": "judge-model",
            "status": "completed",
            "score": 5,
            "comment": "论证完整",
            "error_message": "不应公开",
        }],
    })
    assert payload["manual_override"] is True
    assert payload["manual_score"] == 4
    assert payload["votes"] == [{
        "index": 1,
        "model": "judge-model",
        "status": "completed",
        "score": 5,
        "comment": "论证完整",
    }]


def test_vote_batch_requires_unanimous_scores(monkeypatch):
    updates = []
    finished = []
    monkeypatch.setattr(tasks, "update_vote", lambda vote_id, **values: updates.append((vote_id, values)))
    monkeypatch.setattr(tasks, "finish_attempt", lambda attempt_id, **values: finished.append((attempt_id, values)))
    plan = [
        {"id": 1, "vote_index": 1, "endpoint": "a"},
        {"id": 2, "vote_index": 2, "endpoint": "b"},
        {"id": 3, "vote_index": 3, "endpoint": "c"},
    ]
    score, message = tasks._evaluate_written_votes(
        {"id": 9}, plan, lambda endpoint, _vote_index: (4 if endpoint != "c" else 5, endpoint),
    )
    assert score is None
    assert "不一致" in message
    assert finished == [(9, {"status": "needs_manual_review"})]


def test_vote_retries_only_the_failed_judge(monkeypatch):
    updates = []
    finished = []
    calls = {"a": 0, "b": 0}
    monkeypatch.setattr(tasks, "update_vote", lambda vote_id, **values: updates.append((vote_id, values)))
    monkeypatch.setattr(tasks, "finish_attempt", lambda attempt_id, **values: finished.append((attempt_id, values)))

    def evaluate(endpoint, _vote_index):
        calls[endpoint] += 1
        if endpoint == "b":
            raise RuntimeError("offline")
        return 5, "通过"

    score, message = tasks._evaluate_written_votes(
        {"id": 10},
        [
            {"id": 1, "vote_index": 1, "endpoint": "a"},
            {"id": 2, "vote_index": 2, "endpoint": "b"},
        ],
        evaluate,
    )
    assert score is None
    assert "重试" in message
    assert calls == {"a": 1, "b": 5}
    assert finished == [(10, {"status": "needs_manual_review"})]


def test_disagreement_runs_second_round_with_only_other_judges(monkeypatch):
    updates = []
    finished = []
    reconsidered = []
    monkeypatch.setattr(tasks, "update_vote", lambda vote_id, **values: updates.append((vote_id, values)))
    monkeypatch.setattr(tasks, "finish_attempt", lambda attempt_id, **values: finished.append((attempt_id, values)))
    plan = [
        {"id": 1, "vote_index": 1, "endpoint": "a"},
        {"id": 2, "vote_index": 2, "endpoint": "b"},
        {"id": 3, "vote_index": 3, "endpoint": "c"},
    ]
    first_scores = {"a": 4, "b": 5, "c": 5}

    def first_round(endpoint, vote_index):
        score = first_scores[endpoint]
        return WrittenGradingRound(
            score=score,
            comment=f"首轮 {endpoint}",
            raw_response=f'{{"score":{score},"comment":"{endpoint}"}}',
            prompt=f"prompt-{endpoint}",
            vote_index=vote_index,
        )

    def second_round(endpoint, own_round, peers, round_number):
        reconsidered.append((endpoint, own_round, peers, round_number))
        return WrittenGradingRound(
            score=5,
            comment=f"终轮 {endpoint}",
            raw_response='{"score":5,"deductions":[],"comment":"一致"}',
            prompt=own_round.prompt,
        )

    score, message = tasks._evaluate_written_votes(
        {"id": 11},
        plan,
        first_round,
        second_round,
    )

    assert score == 5
    assert message == "终轮 a"
    assert finished == [(11, {"status": "consensus", "consensus_score": 5})]
    assert len(reconsidered) == 3
    for endpoint, own_round, peers, round_number in reconsidered:
        assert round_number == 2
        assert own_round.prompt == f"prompt-{endpoint}"
        assert {peer["vote_index"] for peer in peers} == {
            vote["vote_index"] for vote in plan if vote["endpoint"] != endpoint
        }
        assert all(peer["round"].prompt != own_round.prompt for peer in peers)


def test_first_round_failure_does_not_start_reconsideration(monkeypatch):
    finished = []
    reconsidered = []
    monkeypatch.setattr(tasks, "update_vote", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tasks, "finish_attempt", lambda attempt_id, **values: finished.append((attempt_id, values)))

    def first_round(endpoint, _vote_index):
        if endpoint == "b":
            raise RuntimeError("offline")
        return WrittenGradingRound(5, "完成", '{"score":5}', "prompt")

    score, message = tasks._evaluate_written_votes(
        {"id": 12},
        [
            {"id": 1, "vote_index": 1, "endpoint": "a"},
            {"id": 2, "vote_index": 2, "endpoint": "b"},
        ],
        first_round,
        lambda *_args: reconsidered.append(True),
    )

    assert score is None
    assert "按间隔重试" in message
    assert reconsidered == []
    assert finished == [(12, {"status": "needs_manual_review"})]


def test_second_round_disagreement_triggers_third_round(monkeypatch):
    finished = []
    reconsidered = []
    monkeypatch.setattr(tasks, "update_vote", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tasks, "finish_attempt", lambda attempt_id, **values: finished.append((attempt_id, values)))

    def round_result(endpoint, scores, label):
        score = scores[endpoint]
        return WrittenGradingRound(
            score,
            f"{label} {endpoint}",
            f'{{"score":{score}}}',
            f"prompt-{endpoint}",
        )

    def reconsider(endpoint, own_round, peers, round_number):
        reconsidered.append((endpoint, round_number, {peer["vote_index"] for peer in peers}))
        scores = {"a": 3, "b": 5} if round_number == 2 else {"a": 5, "b": 5}
        return round_result(endpoint, scores, f"第{round_number}轮")

    score, message = tasks._evaluate_written_votes(
        {"id": 13},
        [
            {"id": 1, "vote_index": 1, "endpoint": "a"},
            {"id": 2, "vote_index": 2, "endpoint": "b"},
        ],
        lambda endpoint, _vote_index: round_result(endpoint, {"a": 4, "b": 5}, "首轮"),
        reconsider,
    )

    assert score == 5
    assert message == "第3轮 a"
    assert finished == [(13, {"status": "consensus", "consensus_score": 5})]
    # 第二轮每位评委各一次，仍分歧后第三轮每位评委再各一次。
    assert sorted((item[0], item[1]) for item in reconsidered) == [
        ("a", 2), ("a", 3), ("b", 2), ("b", 3),
    ]
    for endpoint, round_number, peer_indexes in reconsidered:
        assert peer_indexes == {2 if endpoint == "a" else 1}


def test_third_round_disagreement_requires_manual_review(monkeypatch):
    finished = []
    rounds_seen = []
    monkeypatch.setattr(tasks, "update_vote", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tasks, "finish_attempt", lambda attempt_id, **values: finished.append((attempt_id, values)))

    def round_result(endpoint, scores, label):
        score = scores[endpoint]
        return WrittenGradingRound(
            score,
            f"{label} {endpoint}",
            f'{{"score":{score}}}',
            f"prompt-{endpoint}",
        )

    def reconsider(endpoint, _own, _peers, round_number):
        rounds_seen.append(round_number)
        return round_result(
            endpoint,
            {"a": 3, "b": 5},
            f"第{round_number}轮",
        )

    score, message = tasks._evaluate_written_votes(
        {"id": 14},
        [
            {"id": 1, "vote_index": 1, "endpoint": "a"},
            {"id": 2, "vote_index": 2, "endpoint": "b"},
        ],
        lambda endpoint, _vote_index: round_result(endpoint, {"a": 4, "b": 5}, "首轮"),
        reconsider,
    )

    assert score is None
    assert "第三轮" in message
    assert "仍不一致" in message
    assert rounds_seen == [2, 2, 3, 3]
    assert finished == [(14, {"status": "needs_manual_review"})]


@pytest.mark.parametrize("failures", range(6))
def test_vote_uses_five_opportunities_with_ordered_retry_delays(monkeypatch, failures):
    events = []
    updates = []
    vote = {"id": 1, "vote_index": 1, "endpoint": "a"}
    monkeypatch.setattr(tasks, "update_vote", lambda _id, **values: updates.append(values))
    monkeypatch.setattr(tasks.time, "sleep", lambda seconds: events.append(("wait", seconds)))
    calls = 0

    def evaluate(endpoint):
        nonlocal calls
        assert endpoint == "a"
        calls += 1
        events.append(("call", calls))
        if calls <= failures:
            raise ConnectionError("端点暂不可用")
        return 5, "完成"

    result = tasks._run_written_vote(1, vote, evaluate)
    attempts = min(failures + 1, 5)
    expected_events = [("call", 1)]
    for call_index, delay in enumerate((5, 20, 60, 60)[:attempts - 1], start=2):
        expected_events.extend([("wait", delay), ("call", call_index)])
    assert events == expected_events
    assert updates[-1]["call_attempts"] == attempts
    assert updates[-1]["status"] == ("completed" if failures < 5 else "failed")
    assert ("error" in result) is (failures == 5)


def test_exhausted_json_repair_does_not_restart_grading(monkeypatch):
    calls = []
    updates = []
    monkeypatch.setattr(tasks, "update_vote", lambda _id, **values: updates.append(values))
    monkeypatch.setattr(tasks.time, "sleep", lambda _seconds: pytest.fail("修复耗尽后不能重试评分"))

    def evaluate(_endpoint):
        calls.append(True)
        raise WrittenGradingJSONRepairError("已用完五次修复机会")

    result = tasks._run_written_vote(1, {"id": 1, "endpoint": "a"}, evaluate)

    assert calls == [True]
    assert "error" in result
    assert updates[-1]["status"] == "failed"
    assert updates[-1]["call_attempts"] == 1


def test_vote_does_not_retry_worker_time_limit(monkeypatch):
    calls = []
    monkeypatch.setattr(tasks, "update_vote", lambda *_args, **_kwargs: None)

    def evaluate(_endpoint):
        calls.append(True)
        raise tasks.SoftTimeLimitExceeded()

    with pytest.raises(tasks.SoftTimeLimitExceeded):
        tasks._run_written_vote(1, {"id": 1, "endpoint": "a"}, evaluate)

    assert calls == [True]


def test_same_endpoint_judges_get_distinct_identities_and_targeted_replies(monkeypatch):
    finished = []
    received = []
    endpoint = object()
    plan = [{"id": index, "vote_index": index, "endpoint": endpoint} for index in (1, 2, 3)]
    monkeypatch.setattr(tasks, "update_vote", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tasks, "finish_attempt", lambda _id, **values: finished.append(values))

    def first_round(actual_endpoint, vote_index):
        assert actual_endpoint is endpoint
        return WrittenGradingRound(
            vote_index, f"评委{vote_index}首轮", '{"score":1}',
            f"评委{vote_index}的题面", vote_index=vote_index,
        )

    def reconsider(actual_endpoint, previous, peers, round_number):
        assert actual_endpoint is endpoint
        own_index = previous.vote_index
        received.append((own_index, round_number, peers))
        if round_number == 3:
            for peer in peers:
                assert peer["reply_to_current_judge"] == f"从{peer['vote_index']}回复{own_index}"
                assert peer["round"].vote_index == peer["vote_index"]
        return WrittenGradingRound(
            5 if round_number == 3 else own_index,
            f"评委{own_index}第{round_number}轮", '{"score":5}', previous.prompt,
            peer_replies=tuple(
                {"vote_index": peer["vote_index"], "reply": f"从{own_index}回复{peer['vote_index']}"}
                for peer in peers
            ),
            vote_index=own_index,
        )

    score, comment = tasks._evaluate_written_votes({"id": 1}, plan, first_round, reconsider)

    assert score == 5
    assert comment == "评委1第3轮"
    assert sorted((index, round_number) for index, round_number, _peers in received) == [
        (1, 2), (1, 3), (2, 2), (2, 3), (3, 2), (3, 3),
    ]
    assert finished == [{"status": "consensus", "consensus_score": 5}]
