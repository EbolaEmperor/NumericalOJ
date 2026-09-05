# -*- coding: utf-8 -*-
"""Judge 评分 SSE 的会话链接权限与评测 attempt 一致性。"""

import json

import pytest
from flask import Flask

import backend.oj_modules.ranking.agent_judge.db as db
import backend.oj_modules.routes.ranking_routes as routes
import backend.oj_modules.tasks.ranking.agent_judge as tasks


def _app():
    app = Flask(__name__)
    app.secret_key = "test"
    return app


def test_judge_stream_rejects_non_owner(monkeypatch):
    monkeypatch.setattr(
        routes, "_require_user", lambda: ({"username": "other", "is_admin": 0}, None),
    )
    monkeypatch.setattr(
        routes, "get_ranking_submission",
        lambda sid: {"id": sid, "competition_id": 7, "username": "u1"},
    )

    with _app().test_request_context():
        response = routes.ranking_judge_stream(7, 41)

    assert response.status_code == 403


def test_terminal_stream_snapshot_is_rebuilt_from_canonical_trace(monkeypatch):
    attempt_trace_id = db.agent_judge_trace_id("attempt-current")
    stale = {
        "status": "Accepted",
        "attempt_trace_id": attempt_trace_id,
        "execution_trace": {"trace_messages": [{"text": "rule 17 before setup"}]},
    }
    canonical = {
        "status": "Accepted",
        "attempt_trace_id": attempt_trace_id,
        "execution_trace": {"trace_messages": [{"text": "setup before rule 17"}]},
    }
    monkeypatch.setattr(
        routes, "build_current_judge_snapshot", lambda _sid: canonical,
    )

    assert routes._canonical_terminal_judge_snapshot(
        26, stale, attempt_trace_id,
    ) == canonical


def test_running_stream_snapshot_does_not_force_disk_rebuild(monkeypatch):
    running = {
        "status": "Judging",
        "attempt_trace_id": db.agent_judge_trace_id("attempt-current"),
    }
    monkeypatch.setattr(
        routes, "build_current_judge_snapshot",
        lambda _sid: pytest.fail("running snapshots must keep the low-latency path"),
    )

    assert routes._canonical_terminal_judge_snapshot(
        26, running, running["attempt_trace_id"],
    ) is running


def test_terminal_stream_does_not_close_after_attempt_switch(monkeypatch):
    stale_attempt = db.agent_judge_trace_id("attempt-stale")
    stale = {"status": "Accepted", "attempt_trace_id": stale_attempt}
    current = {
        "status": "Judging",
        "attempt_trace_id": db.agent_judge_trace_id("attempt-new"),
    }
    monkeypatch.setattr(
        routes, "build_current_judge_snapshot", lambda _sid: current,
    )

    assert routes._canonical_terminal_judge_snapshot(
        26, stale, stale_attempt,
    ) is None


def test_cached_terminal_snapshot_is_rejected_after_new_attempt(monkeypatch):
    old = {"status": "Accepted", "attempt_trace_id": db.agent_judge_trace_id("old")}

    class FakeRedis:
        def __init__(self):
            self.deleted = []

        def get(self, _key):
            return json.dumps(old)

        def delete(self, key):
            self.deleted.append(key)

    fake = FakeRedis()
    monkeypatch.setattr(tasks, "_judge_rds", fake)
    monkeypatch.setattr(
        tasks, "get_ranking_submission",
        lambda _sid: {"judge_attempt_id": "new"},
    )
    fresh = {"status": "Queued", "attempt_trace_id": db.agent_judge_trace_id("new")}
    monkeypatch.setattr(tasks, "build_judge_snapshot", lambda _sid: fresh)

    assert tasks.get_judge_progress_snapshot(8) == fresh
    assert fake.deleted == [tasks._judge_progress_key(8)]


def test_terminal_snapshot_is_rebuilt_even_when_cached_attempt_matches(monkeypatch):
    attempt_id = "terminal-attempt"
    cached = {
        "status": "Accepted",
        "attempt_trace_id": db.agent_judge_trace_id(attempt_id),
        "execution_trace": {"trace_messages": [{"text": "stale order"}]},
    }

    class FakeRedis:
        def __init__(self):
            self.get_calls = 0

        def get(self, _key):
            self.get_calls += 1
            return json.dumps(cached)

    fake = FakeRedis()
    monkeypatch.setattr(tasks, "_judge_rds", fake)
    monkeypatch.setattr(
        tasks, "get_ranking_submission",
        lambda _sid: {
            "judge_attempt_id": attempt_id,
            "status": "Accepted",
        },
    )
    canonical = {
        "status": "Accepted",
        "attempt_trace_id": db.agent_judge_trace_id(attempt_id),
        "execution_trace": {"trace_messages": [{"text": "canonical order"}]},
    }
    monkeypatch.setattr(tasks, "build_judge_snapshot", lambda _sid: canonical)

    assert tasks.get_judge_progress_snapshot(8) == canonical
    assert fake.get_calls == 0


def test_build_judge_snapshot_links_current_generic_session(monkeypatch):
    monkeypatch.setattr(db, 'get_ranking_submission', lambda _sid: {
        'id': 9, 'competition_id': 3, 'status': 'Judging',
        'judge_attempt_id': 'attempt-live',
    })
    monkeypatch.setattr(db, 'list_competition_rules', lambda _cid: [])
    monkeypatch.setattr(db, 'list_judge_results', lambda _sid: [])
    calls = []
    from backend.oj_modules.agents import sessions
    monkeypatch.setattr(sessions, 'get_judge_session_for_attempt',
                        lambda *args: calls.append(args) or {'session_id': 'generic-session'})

    snapshot = db.build_judge_snapshot(9)

    assert snapshot['agent_session_id'] == 'generic-session'
    assert calls == [(9, 'attempt-live', 'agent_judge')]
    assert 'execution_trace' not in snapshot


@pytest.mark.parametrize('is_admin', [0, 1])
def test_judge_stream_exposes_results_and_only_admin_session_link(monkeypatch, is_admin):
    snapshot = {
        'submission_id': 41, 'status': 'Accepted', 'rules': [],
        'total_score': 10, 'max_score': 10, 'agent_session_id': 'private-judge-session',
        'execution_trace': {'trace_messages': [{'text': 'private prompt'}]},
    }
    monkeypatch.setattr(routes, '_require_user', lambda: ({'username': 'u1', 'is_admin': is_admin}, None))
    monkeypatch.setattr(routes, 'get_ranking_submission', lambda sid: {'id': sid, 'competition_id': 7, 'username': 'u1'})
    monkeypatch.setattr(routes, 'list_agent_judge_endpoints', lambda *args, **kwargs: [])
    monkeypatch.setattr(routes, 'get_judge_progress_snapshot', lambda _sid: snapshot)
    with _app().test_request_context():
        body = routes.ranking_judge_stream(7, 41).get_data(as_text=True)
    assert '"total_score": 10' in body
    assert ('private-judge-session' in body) is bool(is_admin)
    assert 'execution_trace' not in body
    assert 'private prompt' not in body
    assert snapshot['execution_trace']['trace_messages'][0]['text'] == 'private prompt'


def test_public_projection_redacts_result_secrets_and_fails_closed_without_endpoint_config():
    snapshot = {'agent_session_id': 'private-session', 'error_message': 'key SECRET',
                'rules': [{'evidence': 'key SECRET', 'evidence_html': '<p>key SECRET</p>'}]}
    projected = routes._project_agent_judge_snapshot(snapshot, sensitive_values=('SECRET',))
    assert 'SECRET' not in json.dumps(projected)
    assert 'agent_session_id' not in projected
    closed = routes._project_agent_judge_snapshot(snapshot, redaction_ready=False)
    assert closed['error_message'] == ''
    assert closed['rules'][0]['evidence'] == ''
    assert closed['rules'][0]['evidence_html'] == ''


@pytest.mark.parametrize('is_admin', [0, 1])
def test_reverse_snapshot_only_links_authorized_sessions_and_drops_all_ai_traces(is_admin):
    snapshot = {'steps': [
        {'step_key': 'quality_gate', 'status': 'running', 'agent_session_id': 'quality-session',
         'stdout': 'secret prompt', 'trace_messages': [{'text': 'secret prompt'}]},
        {'step_key': 'agent_answer', 'status': 'running', 'agent_session_id': 'answer-session',
         'stdout': 'answer transcript', 'trace_files': [{'content': 'answer transcript'}]},
    ]}
    projected = routes._project_reverse_judge_snapshot(snapshot, include_internal=bool(is_admin))
    encoded = json.dumps(projected)
    assert ('quality-session' in encoded) is bool(is_admin)
    assert projected['steps'][1]['agent_session_id'] == 'answer-session'
    for hidden in ['trace_messages', 'trace_files', 'stdout', 'secret prompt', 'answer transcript']:
        assert hidden not in encoded


def test_reverse_stream_rejects_another_submission_owner(monkeypatch):
    monkeypatch.setattr(routes, '_require_user', lambda: ({'username': 'other', 'is_admin': 0}, None))
    monkeypatch.setattr(routes, 'get_ranking_submission', lambda sid: {'id': sid, 'competition_id': 7, 'username': 'owner'})
    with _app().test_request_context():
        assert routes.ranking_reverse_judge_stream(7, 41).status_code == 403
