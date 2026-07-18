"""有副作用的入口必须使用非安全 HTTP 方法。"""

from pathlib import Path

from flask import Flask

from oj_modules.routes.auth_routes import auth_bp
from oj_modules.routes.homework_routes import homework_bp


ROOT = Path(__file__).resolve().parents[2]


def test_logout_and_export_task_start_are_post_only():
    app = Flask(__name__)
    app.register_blueprint(auth_bp)
    app.register_blueprint(homework_bp)
    methods_by_rule = {rule.rule: rule.methods for rule in app.url_map.iter_rules()}

    for rule in ('/logout', '/export_student_codes'):
        methods = methods_by_rule[rule]
        assert 'POST' in methods
        assert 'GET' not in methods
        assert 'HEAD' not in methods


def test_checked_in_browser_and_cli_callers_use_post():
    layout = "\n".join(
        path.read_text(encoding='utf-8')
        for path in (
            ROOT / 'templates' / 'layouts' / 'site.html',
            ROOT / 'templates' / 'components' / 'layout' / 'navigation.html',
        )
    )
    homework_template = (
        ROOT / 'templates' / 'admin' / 'homework.html'
    ).read_text(encoding='utf-8')
    admin_auth = (
        ROOT / 'skills' / 'numoj-admin' / 'scripts' / 'numoj_admin_cli' / 'auth.py'
    ).read_text(encoding='utf-8')
    user_auth = (
        ROOT / 'skills' / 'numoj-user' / 'scripts' / 'numoj_user_cli' / 'auth.py'
    ).read_text(encoding='utf-8')
    admin_homework = (
        ROOT / 'skills' / 'numoj-admin' / 'scripts' / 'numoj_admin_cli' / 'homework.py'
    ).read_text(encoding='utf-8')

    assert 'method="post" action="{{ url_for(\'auth.logout\') }}"' in layout
    assert "fetch('/export_student_codes', {" in homework_template
    assert 'method: \'POST\'' in homework_template
    assert 'request("POST", "/logout")' in admin_auth
    assert 'request("POST", "/logout")' in user_auth
    assert 'request("POST", "/export_student_codes"' in admin_homework
