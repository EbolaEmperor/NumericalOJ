from datetime import datetime

from flask import Flask

from backend.oj_modules.api.problem_api import _homework_problem_item
from backend.oj_modules.problems import catalog
from backend.oj_modules.routes import homework_routes


class Cursor:
    def __init__(self, result_sets):
        self.results = list(result_sets)
        self.executions = []

    def execute(self, sql, params=None):
        self.executions.append((' '.join(sql.split()), params))

    def fetchall(self):
        return self.results.pop(0)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass


class Connection:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self):
        return self._cursor

    def close(self):
        pass


def test_student_edu_homework_uses_own_assignment_and_deadline():
    deadline = datetime(2026, 10, 21, 12)
    cursor = Cursor([[
        {'id': 2, 'assignment_id': 7, 'score': 70, 'status': 'graded', 'created_at': deadline},
        {'id': 3, 'assignment_id': 7, 'score': 100, 'status': 'graded', 'created_at': datetime(2026, 10, 22)},
    ]])
    homework = {'id': 5, 'kind': 'edu', 'vibehub_project_id': 4,
                'vibehub_edu_assignment_id': 7, 'vibehub_slug': 'balance',
                'ddl': deadline, 'total_score': 100}
    catalog._attach_user_homework_scores({'C1': [homework]}, '2026001', cursor)
    assert homework['max_score'] == 70
    assert homework['practice_max_score'] == 100
    assert homework['is_completed'] is False
    assert homework['has_submission'] is True
    sql, params = cursor.executions[0]
    assert "es.status='graded'" in sql
    assert 'u.username=%s' in sql
    assert params == ('2026001', 7)
    item = _homework_problem_item(homework, 'C1')
    assert item['url'] == '/vibehub/balance/play?assignment=7'
    assert item['kind'] == 'edu'
    assert item['homework_id'] == 5


def test_edu_completion_count_is_full_score_before_deadline():
    cursor = Cursor([[{'homework_id': 3, 'completed_count': 2}]])
    counts = homework_routes._homework_completion_counts(
        cursor, 'C1', [{'id': 3, 'vibehub_edu_assignment_id': 7}],
    )
    assert counts == {3: 2}
    sql, params = cursor.executions[0]
    assert 'es.score_bp >= 10000' in sql
    assert "es.status = 'graded'" in sql
    assert 'es.created_at <= COALESCE(h.ddl, es.created_at)' in sql
    assert params == ('C1',)


def test_edu_score_export_uses_graded_results_and_deadline(monkeypatch):
    deadline = datetime(2026, 10, 21, 12)
    cursor = Cursor([
        [{'id': 1, 'problem_id': None, 'ranking_competition_id': None,
          'vibehub_project_id': 4, 'vibehub_edu_assignment_id': 7,
          'ddl': deadline, 'problem_title': '动态平衡术'}],
        [{'id': 12, 'username': '2026001'}],
        [
            {'id': 2, 'username': '2026001', 'assignment_id': 7, 'score': 80,
             'status': 'graded', 'created_at': deadline},
            {'id': 3, 'username': '2026001', 'assignment_id': 7, 'score': 100,
             'status': 'graded', 'created_at': datetime(2026, 10, 22)},
        ],
    ])
    monkeypatch.setattr(homework_routes, 'current_user', lambda: {'id': 1, 'is_admin': 1})
    monkeypatch.setattr(homework_routes, 'get_class_by_en', lambda _class_en: {'class_en': 'C1'})
    monkeypatch.setattr(homework_routes, 'get_db_connection', lambda: Connection(cursor))
    app = Flask(__name__)
    with app.test_request_context('/api/admin/homework/exports/scores?sclass=C1'):
        response = homework_routes.export_scores()
    content = response.get_data().decode('gbk')
    assert '用户名,动态平衡术,总分' in content
    assert '2026001,80,80' in content
    sql, params = cursor.executions[-1]
    assert "es.status = 'graded'" in sql
    assert params == (12, 7)
