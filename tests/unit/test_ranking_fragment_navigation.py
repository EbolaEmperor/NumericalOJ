"""打榜赛详情 Fragment 与轻量导航状态的纯单元契约。"""

from pathlib import Path

import pytest
from flask import Flask

from oj_modules.ranking import db as ranking_db
from oj_modules.routes import ranking_routes


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _clear_navigation_cache():
    with ranking_routes._ranking_navigation_state_cache_guard:
        ranking_routes._ranking_navigation_state_cache.clear()
    yield
    with ranking_routes._ranking_navigation_state_cache_guard:
        ranking_routes._ranking_navigation_state_cache.clear()


class _FakeCursor:
    def __init__(self, row, calls):
        self._row = row
        self._calls = calls

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def execute(self, sql, params):
        self._calls.append((sql, params))

    def fetchone(self):
        return dict(self._row) if self._row is not None else None


class _FakeConnection:
    def __init__(self, row, calls):
        self._row = row
        self._calls = calls
        self.closed = False

    def cursor(self):
        return _FakeCursor(self._row, self._calls)

    def close(self):
        self.closed = True


def _navigation_row(**overrides):
    row = {
        'competition_id': 24,
        'scoring_mode': 'elo',
        'is_active': 1,
        'submit_limit_per_window': 5,
        'quota_window_start': '2026-07-29 00:00:00',
        'quota_used': 2,
        'competition_fingerprint': 'competition-v1',
        'submission_count': 7,
        'leaderboard_count': 3,
        'submission_fingerprint_sum': 101,
        'submission_fingerprint_xor': 91,
        'match_count': 5,
        'valid_match_count': 4,
        'match_fingerprint_sum': 202,
        'match_fingerprint_xor': 82,
        'appeal_count': 2,
        'pending_appeal_count': 1,
        'appeal_fingerprint_sum': 303,
        'appeal_fingerprint_xor': 73,
        'attachment_count': 6,
        'attachment_fingerprint_sum': 404,
        'attachment_fingerprint_xor': 64,
        'rule_count': 2,
        'rule_fingerprint_sum': 505,
        'rule_fingerprint_xor': 55,
        'endpoint_count': 1,
        'endpoint_fingerprint_sum': 606,
        'endpoint_fingerprint_xor': 46,
    }
    row.update(overrides)
    return row


def _state(**overrides):
    state = {
        'competition_id': 24,
        'scoring_mode': 'elo',
        'is_active': 1,
        'revision': 'revision-1',
        'quota': {'remaining': 3, 'limit': 5},
        'counts': {
            'leaderboard': 3,
            'matches': 4,
            'all_submissions': 7,
            'appeals': 1,
            'attachments': 6,
        },
    }
    state.update(overrides)
    return state


def _competition(**overrides):
    competition = {
        'id': 24,
        'title': '数值优化挑战',
        'summary': '摘要',
        'description': '# 比赛说明',
        'scoring_mode': 'elo',
        'answer_format': 'json',
        'max_score': 100,
        'is_active': 1,
        'submission_method': 'zip',
        'agent_judge_api_key': None,
        'created_at': '2026-07-29 00:00:00',
    }
    competition.update(overrides)
    return competition


def _app(monkeypatch, *, user=None, competition=None, state=None):
    app = Flask(
        __name__,
        template_folder=str(ROOT / 'templates'),
        static_folder=str(ROOT / 'static'),
    )
    app.config.update(TESTING=True, SECRET_KEY='ranking-fragment-test')
    app.register_blueprint(ranking_routes.ranking_bp)

    active_user = user or {'username': 'student01', 'is_admin': 0}
    active_competition = competition or _competition()
    active_state = state or _state()
    monkeypatch.setattr(
        ranking_routes, 'get_user_by_username', lambda username: active_user,
    )
    monkeypatch.setattr(
        ranking_routes, 'get_competition', lambda competition_id: active_competition,
    )
    monkeypatch.setattr(
        ranking_routes, 'list_competition_files', lambda competition_id: [],
    )
    monkeypatch.setattr(
        ranking_routes, 'get_leaderboard', lambda competition_id: [],
    )
    monkeypatch.setattr(
        ranking_routes,
        'get_ranking_navigation_state',
        lambda competition_id, username=None: active_state,
    )
    return app


def _logged_in_client(app):
    client = app.test_client()
    with client.session_transaction() as session:
        session['username'] = 'student01'
    return client


def test_navigation_db_query_is_single_read_and_tracks_submission_state(monkeypatch):
    calls = []
    rows = [
        _navigation_row(),
        _navigation_row(
            # 同一条 submission 的 status / score 改变时，SQL 聚合值会改变；
            # 行数和 id 不变也必须产生新的 revision。
            submission_fingerprint_sum=999,
            submission_fingerprint_xor=777,
        ),
    ]
    connections = []

    def fake_connection():
        connection = _FakeConnection(rows.pop(0), calls)
        connections.append(connection)
        return connection

    monkeypatch.setattr(ranking_db, 'get_db_connection', fake_connection)

    before = ranking_db.get_ranking_navigation_state(24, 'student01')
    after = ranking_db.get_ranking_navigation_state(24, 'student01')

    assert before['revision'] != after['revision']
    assert before['quota'] == {'remaining': 3, 'limit': 5}
    assert before['counts'] == {
        'leaderboard': 3,
        'matches': 4,
        'all_submissions': 7,
        'appeals': 1,
        'attachments': 6,
    }
    assert len(calls) == 2
    assert all(connection.closed for connection in connections)
    sql = calls[0][0]
    assert 'COALESCE(s.status' in sql
    assert 'CAST(s.score AS CHAR)' in sql
    assert 'CAST(s.elo_rating AS CHAR)' in sql
    assert 'CAST(s.elo_match_count AS CHAR)' in sql
    assert 'm.winner IN (0, 1, 2)' in sql
    assert 'submission_rows AS' in sql
    assert 'match_rows AS' in sql
    assert 'appeal_rows AS' in sql
    assert 'm.details' not in sql
    assert 'm.error_message' not in sql
    assert 'a.reason' not in sql
    assert 's.created_at >= s.quota_window_start' in sql


def test_navigation_revision_is_stable_for_identical_snapshot(monkeypatch):
    row = _navigation_row()
    calls = []
    monkeypatch.setattr(
        ranking_db,
        'get_db_connection',
        lambda: _FakeConnection(row, calls),
    )

    first = ranking_db.get_ranking_navigation_state(24, 'student01')
    second = ranking_db.get_ranking_navigation_state(24, 'student01')

    assert first['revision'] == second['revision']
    assert len(calls) == 2


def test_delete_draw_updates_score_from_original_elo_value(monkeypatch):
    calls = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def execute(self, sql, params):
            calls.append((sql, params))

        def fetchone(self):
            return {
                'id': 8,
                'competition_id': 24,
                'submission_a_id': 11,
                'submission_b_id': 12,
                'winner': 0,
                'rating_a_before': 1400,
                'rating_a_after': 1405,
                'rating_b_before': 1600,
                'rating_b_after': 1595,
            }

    class Connection:
        committed = False
        closed = False

        def cursor(self):
            return Cursor()

        def commit(self):
            self.committed = True

        def close(self):
            self.closed = True

    connection = Connection()
    monkeypatch.setattr(ranking_db, 'get_db_connection', lambda: connection)

    result = ranking_db.delete_elo_match_and_revert(8, 24)

    updates = [
        (' '.join(sql.split()), params)
        for sql, params in calls
        if 'UPDATE ranking_submissions' in sql
    ]
    match_select = ' '.join(calls[0][0].split())
    assert match_select.endswith(
        'WHERE id = %s AND competition_id = %s FOR UPDATE'
    )
    assert len(updates) == 2
    assert all(
        'SET score = elo_rating - %s, elo_rating = elo_rating - %s' in sql
        for sql, _ in updates
    )
    assert updates[0][1] == (5.0, 5.0, 11)
    assert updates[1][1] == (-5.0, -5.0, 12)
    assert result['winner'] == 0
    assert connection.committed is True
    assert connection.closed is True


def test_fragment_returns_normalized_tab_html_revision_and_navigation(monkeypatch):
    app = _app(monkeypatch)
    client = _logged_in_client(app)

    response = client.get('/ranking/24/?tab=leaderboard&fragment=1')

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['success'] is True
    assert payload['tab'] == 'leaderboard'
    assert payload['revision'] == 'revision-1'
    assert payload['navigation']['counts']['submit'] == {
        'remaining': 3,
        'limit': 5,
    }
    assert payload['navigation']['counts']['all_submissions'] is None
    assert payload['navigation']['counts']['appeals'] is None
    assert 'data-ranking-panel' in payload['html']
    assert 'data-ranking-tab="leaderboard"' in payload['html']


def test_fragment_captures_revision_before_reading_tab_content(monkeypatch):
    app = _app(monkeypatch)
    client = _logged_in_client(app)
    events = []

    def navigation_state(competition_id, username=None):
        events.append('revision')
        return _state()

    def files(competition_id):
        events.append('content')
        return []

    monkeypatch.setattr(
        ranking_routes, 'get_ranking_navigation_state', navigation_state,
    )
    monkeypatch.setattr(ranking_routes, 'list_competition_files', files)

    response = client.get('/ranking/24/?tab=description&fragment=1')

    assert response.status_code == 200
    assert events.index('revision') < events.index('content')


def test_fragment_normalizes_forbidden_admin_tab_without_loading_admin_data(monkeypatch):
    app = _app(
        monkeypatch,
        competition=_competition(scoring_mode='absolute'),
        state=_state(scoring_mode='absolute'),
    )
    client = _logged_in_client(app)

    response = client.get('/ranking/24/?tab=edit&fragment=1')

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['tab'] == 'description'
    assert '比赛说明' in payload['html']
    assert payload['navigation']['permissions']['edit'] is False
    assert payload['navigation']['permissions']['matches'] is False


def test_matches_fragment_bypasses_stale_list_cache(monkeypatch):
    app = _app(monkeypatch)
    client = _logged_in_client(app)
    calls = []

    def fresh_matches(competition_id, page, per_page, username=None):
        calls.append((competition_id, page, per_page, username))
        return [], 1, 0

    monkeypatch.setattr(ranking_routes, 'list_competition_matches', fresh_matches)
    monkeypatch.setattr(
        ranking_routes,
        'fetch_competition_matches_cached',
        lambda *args, **kwargs: pytest.fail('Fragment 不应读取 30s 对战列表缓存'),
    )

    response = client.get('/ranking/24/?tab=matches&fragment=1')

    assert response.status_code == 200
    assert response.get_json()['tab'] == 'matches'
    assert calls == [(24, 1, ranking_routes.MATCHES_PER_PAGE, None)]


def test_navigation_cache_coalesces_global_snapshot_but_keeps_user_quota(monkeypatch):
    global_calls = []
    quota_calls = []

    def global_state(competition_id, username=None):
        global_calls.append((competition_id, username))
        return _state(quota=None)

    def quota(competition_id, username, comp=None):
        quota_calls.append((competition_id, username))
        used = 1 if username == 'student01' else 2
        return {
            'limit': 5,
            'used': used,
            'remaining': 5 - used,
            'window_start': '2026-07-29 00:00:00',
        }

    monkeypatch.setattr(
        ranking_routes, 'get_ranking_navigation_state', global_state,
    )
    monkeypatch.setattr(ranking_routes, 'get_submission_quota', quota)

    first = ranking_routes._get_ranking_navigation_state_for_request(
        _competition(),
        {'username': 'student01', 'is_admin': 0},
        False,
    )
    second = ranking_routes._get_ranking_navigation_state_for_request(
        _competition(),
        {'username': 'student02', 'is_admin': 0},
        False,
    )

    assert global_calls == [(24, None)]
    assert quota_calls == [(24, 'student01'), (24, 'student02')]
    assert first['quota'] == {'limit': 5, 'remaining': 4}
    assert second['quota'] == {'limit': 5, 'remaining': 3}
    assert first['revision'] != second['revision']


def test_navigation_cache_has_a_fixed_upper_bound(monkeypatch):
    monkeypatch.setattr(
        ranking_routes,
        'get_ranking_navigation_state',
        lambda competition_id, username=None: _state(
            competition_id=competition_id,
            quota=None,
        ),
    )

    for competition_id in range(
        1, ranking_routes.RANKING_NAVIGATION_STATE_CACHE_MAX + 20,
    ):
        ranking_routes._get_ranking_navigation_state_cached(competition_id)

    assert (
        len(ranking_routes._ranking_navigation_state_cache)
        <= ranking_routes.RANKING_NAVIGATION_STATE_CACHE_MAX
    )


def test_navigation_state_hides_admin_quota_and_exposes_mode_permissions(monkeypatch):
    admin = {'username': 'admin', 'is_admin': 1}
    app = _app(
        monkeypatch,
        user=admin,
        competition=_competition(scoring_mode='agent_judge'),
        state=_state(scoring_mode='agent_judge'),
    )
    client = _logged_in_client(app)

    response = client.get('/ranking/24/navigation-state')

    assert response.status_code == 200
    payload = response.get_json()
    assert payload == {
        'success': True,
        'revision': 'revision-1',
        'navigation': {
            'competition_id': 24,
            'scoring_mode': 'agent_judge',
            'is_admin': True,
            'is_active': True,
            'permissions': {
                'description': True,
                'submit': True,
                'leaderboard': True,
                'matches': False,
                'all_submissions': True,
                'appeals': True,
                'batch_eval': True,
                'edit': True,
            },
            'counts': {
                'submit': None,
                'leaderboard': 3,
                'matches': 4,
                'all_submissions': 7,
                'appeals': 1,
                'attachments': 6,
            },
        },
    }


def test_detail_panel_dispatches_each_tab_once():
    source = (
        ROOT / 'templates' / 'ranking' / 'components' / 'detail_panel.html'
    ).read_text(encoding='utf-8')
    assert 'data-ranking-panel' in source
    assert 'data-ranking-tab="{{ tab }}"' in source
    for name in (
        'description',
        'submit',
        'leaderboard',
        'matches',
        'submissions',
        'appeals',
        'batch_evaluate',
        'settings',
    ):
        assert source.count(
            f"{{% include 'ranking/tabs/{name}.html' %}}"
        ) == 1
