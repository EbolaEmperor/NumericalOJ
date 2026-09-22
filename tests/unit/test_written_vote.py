# -*- coding: utf-8 -*-

import pytest

from backend.oj_modules.ai.grading import WrittenGradingRound
from backend.oj_modules.problems.written_vote import (
    WrittenVoteConfigError,
    deserialize_written_vote_config,
    normalize_written_vote_config,
    serialize_written_vote_config,
)
from backend.oj_modules.tasks import written_homework_tasks as tasks
from backend.oj_modules.submissions.written_voting import public_attempt_payload


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
        {"id": 1, "endpoint": "a"},
        {"id": 2, "endpoint": "b"},
        {"id": 3, "endpoint": "c"},
    ]
    score, message = tasks._evaluate_written_votes(
        {"id": 9}, plan, lambda endpoint: (4 if endpoint != "c" else 5, endpoint),
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

    def evaluate(endpoint):
        calls[endpoint] += 1
        if endpoint == "b":
            raise RuntimeError("offline")
        return 5, "通过"

    score, message = tasks._evaluate_written_votes(
        {"id": 10},
        [{"id": 1, "endpoint": "a"}, {"id": 2, "endpoint": "b"}],
        evaluate,
    )
    assert score is None
    assert "重试" in message
    assert calls == {"a": 1, "b": 3}
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

    def first_round(endpoint):
        score = first_scores[endpoint]
        return WrittenGradingRound(
            score=score,
            comment=f"首轮 {endpoint}",
            raw_response=f'{{"score":{score},"comment":"{endpoint}"}}',
            prompt=f"prompt-{endpoint}",
        )

    def second_round(endpoint, own_round, peers):
        reconsidered.append((endpoint, own_round, peers))
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
    for endpoint, own_round, peers in reconsidered:
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

    def first_round(endpoint):
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
    assert "连续重试" in message
    assert reconsidered == []
    assert finished == [(12, {"status": "needs_manual_review"})]


def test_second_round_disagreement_requires_manual_review(monkeypatch):
    finished = []
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

    score, message = tasks._evaluate_written_votes(
        {"id": 13},
        [
            {"id": 1, "vote_index": 1, "endpoint": "a"},
            {"id": 2, "vote_index": 2, "endpoint": "b"},
        ],
        lambda endpoint: round_result(endpoint, {"a": 4, "b": 5}, "首轮"),
        lambda endpoint, _own, _peers: round_result(
            endpoint,
            {"a": 3, "b": 5},
            "第二轮",
        ),
    )

    assert score is None
    assert "第二轮" in message
    assert "仍不一致" in message
    assert finished == [(13, {"status": "needs_manual_review"})]
