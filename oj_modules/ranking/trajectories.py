"""ELO 在役提交搜索与得分轨迹的只读应用服务。"""

from oj_modules.ranking.db import (
    get_active_elo_trajectory_rows,
    search_active_elo_submissions,
)


SEARCH_LIMIT = 50
MAX_SELECTED = 6


def _format_datetime(value):
    if value is None:
        return ''
    try:
        return value.strftime('%Y-%m-%d %H:%M:%S')
    except AttributeError:
        return str(value)


def search_submissions(competition_id, username_q=None):
    """返回前端选择器使用的在役提交，并标明结果是否被截断。"""
    rows = search_active_elo_submissions(
        competition_id,
        username_q,
        limit=SEARCH_LIMIT + 1,
    )
    truncated = len(rows) > SEARCH_LIMIT
    return [
        {
            'id': int(row.get('id') or 0),
            'username': row.get('username') or '',
            'rating': float(row.get('elo_rating') or 0),
            'match_count': int(row.get('elo_match_count') or 0),
            'created_at': _format_datetime(row.get('created_at')),
        }
        for row in rows[:SEARCH_LIMIT]
    ], truncated


def _match_result(winner, side):
    if winner not in (0, 1, 2):
        return 'failed'
    if winner == 0:
        return 'draw'
    return 'win' if winner == side else 'loss'


def build_series(competition_id, submission_ids):
    """按所选提交涉及的全局对战时间线构造连续 ELO 轨迹。

    返回 ``(series, missing_ids)``。若选择后提交恰好退役，调用方可以用
    ``missing_ids`` 提示用户重新选择，而不会把退役记录混入当前观察结果。
    每个时间点对应一场按时间排序的对战；未参战提交沿用上一时间点的分数。
    """
    submissions, matches = get_active_elo_trajectory_rows(
        competition_id,
        submission_ids,
    )
    submissions_by_id = {int(row['id']): row for row in submissions}
    missing_ids = [sid for sid in submission_ids if sid not in submissions_by_id]
    if missing_ids:
        return [], missing_ids

    matches_by_submission = {submission_id: [] for submission_id in submission_ids}
    for row in matches:
        a_id = int(row.get('submission_a_id') or 0)
        b_id = int(row.get('submission_b_id') or 0)
        if a_id in matches_by_submission:
            matches_by_submission[a_id].append((row, 'a'))
        if b_id in matches_by_submission:
            matches_by_submission[b_id].append((row, 'b'))

    states = {}
    series_by_submission = {}
    for submission_id in submission_ids:
        submission = submissions_by_id[submission_id]
        history = matches_by_submission[submission_id]
        if history:
            first_match, first_side = history[0]
            initial_rating = first_match.get(
                'rating_a_before' if first_side == 'a' else 'rating_b_before'
            )
        else:
            initial_rating = submission.get('elo_rating')
        states[submission_id] = float(initial_rating or 0)
        series_by_submission[submission_id] = {
            'submission_id': submission_id,
            'username': submission.get('username') or '',
            'current_rating': float(submission.get('elo_rating') or 0),
            'match_count': int(submission.get('elo_match_count') or 0),
            'recorded_match_count': len(history),
            'created_at': _format_datetime(submission.get('created_at')),
            'points': [{
                'sequence': 0,
                'match_id': None,
                'created_at': _format_datetime(submission.get('created_at')),
                'rating': states[submission_id],
                'delta': 0.0,
                'opponent': '',
                'result': 'initial',
                'participated': False,
                'matchup': '',
            }],
        }

    for sequence, match in enumerate(matches, start=1):
        a_id = int(match.get('submission_a_id') or 0)
        b_id = int(match.get('submission_b_id') or 0)
        raw_winner = match.get('winner')
        winner = int(raw_winner) if raw_winner is not None else -1
        username_a = match.get('username_a') or ''
        username_b = match.get('username_b') or ''
        matchup = ' vs '.join(name for name in (username_a, username_b) if name)

        for submission_id in submission_ids:
            is_a = submission_id == a_id
            is_b = submission_id == b_id
            participated = is_a or is_b
            if participated:
                side = 'a' if is_a else 'b'
                before = float(match.get(f'rating_{side}_before') or 0)
                after = float(match.get(f'rating_{side}_after') or 0)
                states[submission_id] = after
                opponent = username_b if is_a else username_a
                result = _match_result(winner, 1 if is_a else 2)
                delta = after - before
            else:
                opponent = ''
                result = 'unchanged'
                delta = 0.0

            series_by_submission[submission_id]['points'].append({
                'sequence': sequence,
                'match_id': int(match.get('id') or 0),
                'created_at': _format_datetime(match.get('created_at')),
                'rating': states[submission_id],
                'delta': delta,
                'opponent': opponent,
                'result': result,
                'participated': participated,
                'matchup': matchup,
            })

    return [series_by_submission[sid] for sid in submission_ids], []
