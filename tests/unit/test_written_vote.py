# -*- coding: utf-8 -*-

import pytest

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
