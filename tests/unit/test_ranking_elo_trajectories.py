"""ELO 在役提交搜索与历史轨迹查询的数据库契约。"""

from oj_modules.ranking import db as ranking_db
from oj_modules.ranking import trajectories


class _Cursor:
    def __init__(self, row_sets):
        self.row_sets = list(row_sets)
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def execute(self, sql, params=None):
        self.calls.append((sql, params))

    def fetchall(self):
        return self.row_sets.pop(0) if self.row_sets else []


class _Connection:
    def __init__(self, cursor):
        self.fake_cursor = cursor
        self.closed = False

    def cursor(self):
        return self.fake_cursor

    def close(self):
        self.closed = True


def test_elo_trajectory_selection_limit_is_six():
    assert trajectories.MAX_SELECTED == 6


def test_search_active_elo_submissions_limits_scope_and_fuzzy_matches_username(monkeypatch):
    cursor = _Cursor([[
        {
            'id': 31,
            'username': 'alice',
            'elo_rating': 1512.5,
            'elo_match_count': 4,
            'created_at': '2026-08-24 10:00:00',
        },
    ]])
    connection = _Connection(cursor)
    monkeypatch.setattr(ranking_db, 'get_db_connection', lambda: connection)

    rows = ranking_db.search_active_elo_submissions(17, ' ali ', limit=51)

    assert rows[0]['id'] == 31
    sql, params = cursor.calls[0]
    normalized_sql = ' '.join(sql.split())
    assert "status = 'Active'" in normalized_sql
    assert 'elo_in_pool = 1' in normalized_sql
    assert 'elo_rating IS NOT NULL' in normalized_sql
    assert 'username LIKE %s' in normalized_sql
    assert params == (17, '%ali%', 51)
    assert connection.closed is True


def test_get_active_elo_trajectory_rows_reads_only_selected_active_submissions(monkeypatch):
    submissions = [
        {'id': 7, 'username': 'alice', 'elo_rating': 1510.0},
        {'id': 9, 'username': 'alice', 'elo_rating': 1490.0},
    ]
    matches = [
        {
            'id': 41,
            'submission_a_id': 7,
            'submission_b_id': 12,
            'rating_a_before': 1500.0,
            'rating_a_after': 1510.0,
        },
    ]
    cursor = _Cursor([submissions, matches])
    connection = _Connection(cursor)
    monkeypatch.setattr(ranking_db, 'get_db_connection', lambda: connection)

    actual_submissions, actual_matches = ranking_db.get_active_elo_trajectory_rows(
        17, [9, 7, 9],
    )

    assert actual_submissions == submissions
    assert actual_matches == matches
    assert len(cursor.calls) == 2
    metadata_sql, metadata_params = cursor.calls[0]
    history_sql, history_params = cursor.calls[1]
    normalized_metadata = ' '.join(metadata_sql.split())
    normalized_history = ' '.join(history_sql.split())
    assert "status = 'Active'" in normalized_metadata
    assert 'elo_in_pool = 1' in normalized_metadata
    assert metadata_params == (17, 9, 7)
    assert 'm.submission_a_id IN (%s,%s)' in normalized_history
    assert 'm.submission_b_id IN (%s,%s)' in normalized_history
    assert 'ORDER BY m.created_at ASC, m.id ASC' in normalized_history
    assert history_params == (17, 7, 9, 7, 9)
    assert connection.closed is True


def test_get_active_elo_trajectory_rows_skips_history_query_when_all_selected_retired(monkeypatch):
    cursor = _Cursor([[]])
    connection = _Connection(cursor)
    monkeypatch.setattr(ranking_db, 'get_db_connection', lambda: connection)

    assert ranking_db.get_active_elo_trajectory_rows(17, [7]) == ([], [])
    assert len(cursor.calls) == 1
    assert connection.closed is True


def test_build_series_uses_one_global_timeline_and_carries_idle_ratings(monkeypatch):
    submissions = [
        {'id': 71, 'username': 'alice', 'elo_rating': 1516.0, 'elo_match_count': 1},
        {'id': 72, 'username': 'bob', 'elo_rating': 1500.0, 'elo_match_count': 2},
        {'id': 73, 'username': 'charles', 'elo_rating': 1484.0, 'elo_match_count': 1},
    ]
    matches = [
        {
            'id': 81,
            'submission_a_id': 71,
            'submission_b_id': 72,
            'winner': 1,
            'rating_a_before': 1500.0,
            'rating_a_after': 1516.0,
            'rating_b_before': 1500.0,
            'rating_b_after': 1484.0,
            'username_a': 'alice',
            'username_b': 'bob',
            'created_at': '2026-08-24 10:00:00',
        },
        {
            'id': 82,
            'submission_a_id': 72,
            'submission_b_id': 73,
            'winner': 1,
            'rating_a_before': 1484.0,
            'rating_a_after': 1500.0,
            'rating_b_before': 1500.0,
            'rating_b_after': 1484.0,
            'username_a': 'bob',
            'username_b': 'charles',
            'created_at': '2026-08-24 11:00:00',
        },
    ]
    monkeypatch.setattr(
        trajectories,
        'get_active_elo_trajectory_rows',
        lambda competition_id, submission_ids: (submissions, matches),
    )

    series, missing_ids = trajectories.build_series(17, [71, 72, 73])

    assert missing_ids == []
    assert [[point['sequence'] for point in item['points']] for item in series] == [
        [0, 1, 2],
        [0, 1, 2],
        [0, 1, 2],
    ]
    assert [[point['match_id'] for point in item['points']] for item in series] == [
        [None, 81, 82],
        [None, 81, 82],
        [None, 81, 82],
    ]
    assert [[point['rating'] for point in item['points']] for item in series] == [
        [1500.0, 1516.0, 1516.0],
        [1500.0, 1484.0, 1500.0],
        [1500.0, 1500.0, 1484.0],
    ]
    assert [[point['participated'] for point in item['points']] for item in series] == [
        [False, True, False],
        [False, True, True],
        [False, False, True],
    ]
    assert [item['recorded_match_count'] for item in series] == [1, 2, 1]
    assert series[0]['points'][2]['result'] == 'unchanged'
    assert series[2]['points'][1]['matchup'] == 'alice vs bob'
