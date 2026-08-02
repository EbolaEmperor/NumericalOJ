# -*- coding: utf-8 -*-

from flask import Flask

from oj_modules.api import admin_api
from oj_modules.api.helpers import public_user
from oj_modules.classroom.membership import LastMembershipError
from oj_modules.routes import admin_user_routes, class_management_routes


class _Cursor:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []
        self.rowcount = 0
        self._one = None
        self._all = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def execute(self, sql, params=None):
        compact = ' '.join(str(sql).split())
        self.calls.append((compact, params))
        self.rowcount = 0
        self._one, self._all, self.rowcount = self.handler(compact, params)

    def fetchone(self):
        value = self._one
        self._one = None
        return value

    def fetchall(self):
        values = self._all
        self._all = []
        return values


class _Connection:
    def __init__(self, cursor):
        self.cursor_object = cursor
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def cursor(self):
        return self.cursor_object

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


def _app():
    app = Flask(__name__)
    app.secret_key = 'test-secret'
    return app


def test_removed_class_switch_routes_are_not_registered():
    app = _app()
    app.register_blueprint(class_management_routes.class_management_bp)
    app.register_blueprint(admin_user_routes.admin_user_bp)
    rules = {rule.rule for rule in app.url_map.iter_rules()}

    assert '/me/set_primary_class' not in rules
    assert '/admin/edit_user_ajax' not in rules
    assert '/admin/grant_user_admin_ajax' in rules


def test_me_classes_returns_only_equal_memberships(monkeypatch):
    app = _app()
    memberships = [
        {'class_en': 'C1', 'class_cn': '一班'},
        {'class_en': 'C2', 'class_cn': '二班'},
    ]
    all_classes = memberships + [{'class_en': 'C3', 'class_cn': '三班'}]
    monkeypatch.setattr(
        class_management_routes,
        'current_user',
        lambda: {'id': 7, 'username': 'alice', 'is_admin': 0},
    )
    monkeypatch.setattr(
        class_management_routes,
        'get_user_classes',
        lambda _user_id: memberships,
    )
    monkeypatch.setattr(
        class_management_routes,
        'get_all_classes',
        lambda: all_classes,
    )
    monkeypatch.setattr(
        class_management_routes,
        'attach_class_logos',
        lambda classes: classes,
    )

    with app.test_request_context('/me/classes'):
        response = class_management_routes.get_my_classes()

    assert response.get_json() == {
        'success': True,
        'memberships': memberships,
        'all_classes': all_classes,
    }


def test_self_leave_delegates_atomic_role_policy_to_membership_service(
        monkeypatch):
    app = _app()
    calls = []
    monkeypatch.setattr(
        class_management_routes,
        'is_class_adjust_enabled',
        lambda: True,
    )
    monkeypatch.setattr(
        class_management_routes,
        'leave_class_membership',
        lambda user_id, class_en: calls.append((user_id, class_en)),
    )
    monkeypatch.setattr(
        class_management_routes,
        '_invalidate_problem_list_cache_for_user',
        lambda **_kwargs: None,
    )

    for user in (
        {'id': 7, 'username': 'student', 'is_admin': 0},
        {'id': 8, 'username': 'teacher', 'is_admin': 1},
    ):
        monkeypatch.setattr(
            class_management_routes,
            'current_user',
            lambda user=user: user,
        )
        with app.test_request_context(
            '/me/leave_class',
            method='POST',
            data={'class_en': 'C1'},
        ):
            response = class_management_routes.leave_class()
        assert response.get_json()['success'] is True
        assert calls[-1] == (user['id'], 'C1')


def test_class_adjust_switch_only_blocks_students(monkeypatch):
    app = _app()
    calls = []
    admin = {'id': 8, 'username': 'teacher', 'is_admin': 1}
    monkeypatch.setattr(
        class_management_routes,
        'current_user',
        lambda: admin,
    )
    monkeypatch.setattr(
        class_management_routes,
        'is_class_adjust_enabled',
        lambda: False,
    )
    monkeypatch.setattr(
        class_management_routes,
        'get_class_by_en',
        lambda class_en: {'class_en': class_en, 'class_cn': '一班'},
    )
    monkeypatch.setattr(
        class_management_routes,
        'add_class_membership',
        lambda user_id, class_en: (
            calls.append(('join', user_id, class_en)) or True
        ),
    )
    monkeypatch.setattr(
        class_management_routes,
        'leave_class_membership',
        lambda user_id, class_en: calls.append(
            ('leave', user_id, class_en)
        ),
    )
    monkeypatch.setattr(
        class_management_routes,
        '_invalidate_problem_list_cache_for_user',
        lambda **_kwargs: None,
    )

    with app.test_request_context(
        '/me/join_class',
        method='POST',
        data={'class_en': 'C1'},
    ):
        join_response = class_management_routes.join_class()
    with app.test_request_context(
        '/me/leave_class',
        method='POST',
        data={'class_en': 'C1'},
    ):
        leave_response = class_management_routes.leave_class()

    assert join_response.get_json()['success'] is True
    assert leave_response.get_json()['success'] is True
    assert calls == [
        ('join', admin['id'], 'C1'),
        ('leave', admin['id'], 'C1'),
    ]


def test_disabled_class_adjust_switch_rejects_student_join_and_leave(
        monkeypatch):
    app = _app()
    monkeypatch.setattr(
        class_management_routes,
        'current_user',
        lambda: {'id': 7, 'username': 'student', 'is_admin': 0},
    )
    monkeypatch.setattr(
        class_management_routes,
        'is_class_adjust_enabled',
        lambda: False,
    )

    for path, handler in (
        ('/me/join_class', class_management_routes.join_class),
        ('/me/leave_class', class_management_routes.leave_class),
    ):
        with app.test_request_context(
            path,
            method='POST',
            data={'class_en': 'C1'},
        ):
            response, status = handler()
        assert status == 403
        assert response.get_json() == {
            'success': False,
            'message': '当前不允许调整班级，请联系老师',
        }


def test_class_membership_routes_do_not_expose_database_errors(monkeypatch):
    app = _app()
    monkeypatch.setattr(
        class_management_routes,
        'current_user',
        lambda: {'id': 7, 'username': 'student', 'is_admin': 0},
    )
    monkeypatch.setattr(
        class_management_routes,
        'is_class_adjust_enabled',
        lambda: True,
    )
    monkeypatch.setattr(
        class_management_routes,
        'get_class_by_en',
        lambda class_en: {'class_en': class_en, 'class_cn': '一班'},
    )

    def fail_with_internal_detail(*_args, **_kwargs):
        raise RuntimeError('sensitive database constraint detail')

    monkeypatch.setattr(
        class_management_routes,
        'add_class_membership',
        fail_with_internal_detail,
    )
    monkeypatch.setattr(
        class_management_routes,
        'leave_class_membership',
        fail_with_internal_detail,
    )

    for path, handler, expected_message in (
        (
            '/me/join_class',
            class_management_routes.join_class,
            '加入班级失败，请稍后再试',
        ),
        (
            '/me/leave_class',
            class_management_routes.leave_class,
            '退出班级失败，请稍后再试',
        ),
    ):
        with app.test_request_context(
            path,
            method='POST',
            data={'class_en': 'C1'},
        ):
            response, status = handler()
        assert status == 500
        assert response.get_json() == {
            'success': False,
            'message': expected_message,
        }


def test_self_leave_reports_last_membership_clearly(monkeypatch):
    app = _app()
    monkeypatch.setattr(
        class_management_routes,
        'current_user',
        lambda: {'id': 7, 'username': 'student', 'is_admin': 0},
    )
    monkeypatch.setattr(
        class_management_routes,
        'is_class_adjust_enabled',
        lambda: True,
    )

    def reject_last(*_args, **_kwargs):
        raise LastMembershipError('至少需要保留一个班级')

    monkeypatch.setattr(
        class_management_routes,
        'leave_class_membership',
        reject_last,
    )
    with app.test_request_context(
        '/me/leave_class',
        method='POST',
        data={'class_en': 'C1'},
    ):
        response, status = class_management_routes.leave_class()

    assert status == 400
    assert response.get_json() == {
        'success': False,
        'message': '至少需要保留一个班级',
    }


def test_admin_removal_delegates_atomic_role_policy_to_membership_service(
        monkeypatch):
    app = _app()
    calls = []
    monkeypatch.setattr(
        class_management_routes,
        'current_user',
        lambda: {'id': 1, 'username': 'admin', 'is_admin': 1},
    )
    monkeypatch.setattr(
        class_management_routes,
        'remove_class_membership',
        lambda user_id, class_en: (
            calls.append((user_id, class_en)) or True
        ),
    )
    monkeypatch.setattr(
        class_management_routes,
        '_invalidate_problem_list_cache_for_user',
        lambda **_kwargs: None,
    )

    for target in (
        {'id': 7, 'username': 'student', 'is_admin': 0},
        {'id': 8, 'username': 'teacher', 'is_admin': 1},
    ):
        monkeypatch.setattr(
            class_management_routes,
            'get_user_by_id',
            lambda _user_id, target=target: target,
        )
        with app.test_request_context(
            '/admin/remove_user_from_class',
            method='POST',
            data={'user_id': str(target['id']), 'class_en': 'C1'},
        ):
            response = class_management_routes.remove_user_from_class()
        assert response.get_json()['success'] is True
        assert calls[-1] == (target['id'], 'C1')


def test_public_user_does_not_publish_a_singular_class_snapshot():
    assert public_user({
        'id': 7,
        'username': 'alice',
        'email': 'alice@example.com',
        'class': 'C1',
        'class_cn': '一班',
        'is_admin': 0,
    }) == {
        'id': 7,
        'username': 'alice',
        'email': 'alice@example.com',
        'is_admin': 0,
    }


def test_admin_users_api_returns_equal_classes_and_admin_flag(monkeypatch):
    app = _app()

    def handler(sql, _params):
        if sql.startswith('SELECT COUNT(*) AS total'):
            return {'total': 1}, [], 0
        if sql.startswith('SELECT u.id, u.username, u.email, u.is_admin'):
            return None, [{
                'id': 7,
                'username': 'alice',
                'email': 'alice@example.com',
                'is_admin': 1,
            }], 0
        if sql.startswith('SELECT m.user_id, m.class_en, ct.class_cn'):
            return None, [
                {'user_id': 7, 'class_en': 'C1', 'class_cn': '一班'},
                {'user_id': 7, 'class_en': 'C2', 'class_cn': '二班'},
            ], 0
        raise AssertionError(sql)

    cursor = _Cursor(handler)
    conn = _Connection(cursor)
    monkeypatch.setattr(
        admin_api,
        'current_user',
        lambda: {'id': 1, 'username': 'admin', 'is_admin': 1},
    )
    monkeypatch.setattr(admin_api, 'get_db_connection', lambda: conn)
    monkeypatch.setattr(
        admin_api,
        'get_all_classes',
        lambda: [
            {'class_en': 'C1', 'class_cn': '一班'},
            {'class_en': 'C2', 'class_cn': '二班'},
        ],
    )

    with app.test_request_context('/api/admin/users'):
        payload = admin_api.users().get_json()

    user = payload['users'][0]
    assert user == {
        'id': 7,
        'username': 'alice',
        'email': 'alice@example.com',
        'is_admin': 1,
        'classes': [
            {'class_en': 'C1', 'class_cn': '一班'},
            {'class_en': 'C2', 'class_cn': '二班'},
        ],
        'classes_display': '一班(C1) / 二班(C2)',
    }
    sql_text = '\n'.join(sql for sql, _params in cursor.calls)
    assert 'u.class' not in sql_text
    assert 'is_primary' not in sql_text


def test_grant_user_admin_is_one_way_and_idempotent(monkeypatch):
    app = _app()
    monkeypatch.setattr(
        admin_user_routes,
        'current_user',
        lambda: {'id': 1, 'username': 'admin', 'is_admin': 1},
    )
    monkeypatch.setattr(
        admin_user_routes,
        '_invalidate_problem_list_cache_for_user',
        lambda **_kwargs: None,
    )

    for initial_admin, expected_granted in ((0, True), (1, False)):
        def handler(sql, _params, initial_admin=initial_admin):
            if sql.startswith('SELECT id, username, is_admin FROM users'):
                return {
                    'id': 7,
                    'username': 'alice',
                    'is_admin': initial_admin,
                }, [], 0
            if sql.startswith('UPDATE users SET is_admin=1'):
                return None, [], 1
            raise AssertionError(sql)

        cursor = _Cursor(handler)
        conn = _Connection(cursor)
        monkeypatch.setattr(
            admin_user_routes,
            'get_db_connection',
            lambda conn=conn: conn,
        )
        with app.test_request_context(
            '/admin/grant_user_admin_ajax',
            method='POST',
            data={'user_id': '7'},
        ):
            payload = admin_user_routes.grant_user_admin_ajax().get_json()

        assert payload == {
            'success': True,
            'message': (
                '管理员权限已授予'
                if expected_granted
                else '该用户已经是管理员'
            ),
            'user_id': 7,
            'is_admin': True,
            'granted': expected_granted,
        }
        assert conn.commits == 1
        updates = [
            sql for sql, _params in cursor.calls
            if sql.startswith('UPDATE users SET is_admin=1')
        ]
        assert bool(updates) is expected_granted


def test_problem_scores_aggregate_every_user_class(monkeypatch):
    app = _app()

    def handler(sql, _params):
        if sql.startswith('SELECT u.id, u.username, ms.score'):
            return None, [{
                'id': 7,
                'username': 'alice',
                'score': 95,
            }], 0
        if sql.startswith('SELECT m.user_id, m.class_en, ct.class_cn'):
            return None, [
                {'user_id': 7, 'class_en': 'C1', 'class_cn': '一班'},
                {'user_id': 7, 'class_en': 'C2', 'class_cn': '二班'},
            ], 0
        raise AssertionError(sql)

    cursor = _Cursor(handler)
    conn = _Connection(cursor)
    monkeypatch.setattr(
        admin_user_routes,
        'current_user',
        lambda: {'id': 1, 'username': 'admin', 'is_admin': 1},
    )
    monkeypatch.setattr(
        admin_user_routes,
        'get_problem_title',
        lambda _problem_id: {'title': '题目', 'max_score': 100},
    )
    monkeypatch.setattr(
        admin_user_routes,
        'get_db_connection',
        lambda: conn,
    )

    with app.test_request_context('/admin/problem_scores/5'):
        payload = admin_user_routes.get_problem_scores(5).get_json()

    assert payload['scores'] == [{
        'user_id': 7,
        'username': 'alice',
        'classes': [
            {'class_en': 'C1', 'class_cn': '一班'},
            {'class_en': 'C2', 'class_cn': '二班'},
        ],
        'classes_display': '一班 / 二班',
        'score': 95,
    }]
