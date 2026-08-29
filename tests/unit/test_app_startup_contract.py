import ast
import configparser
from pathlib import Path
import runpy
import sys
import threading
import types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pymysql
import pytest
from flask import (
    Flask,
    Response,
    copy_current_request_context,
    jsonify,
    request,
    send_from_directory,
)
from flask.globals import request_ctx as _flask_request_ctx

from oj_modules import config as app_config
from oj_modules.infrastructure.mysql import (
    MySQLPoolExhausted,
    begin_mysql_pool_exhaustion_tracking,
    current_mysql_pool_exhaustion,
    end_mysql_pool_exhaustion_tracking,
)
from oj_modules.security.login_guard import is_api_request
from oj_modules.shared.static_delivery import PrecompressedStaticFlask


ROOT = Path(__file__).resolve().parents[2]
OJ_PATH = ROOT / 'oj.py'


def _called_name(node):
    function = node.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        return function.attr
    return None


def _tree():
    return ast.parse(OJ_PATH.read_text(encoding='utf-8'), filename=str(OJ_PATH))


def _top_level_call(name):
    matches = [
        statement
        for statement in _tree().body
        if isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Call)
        and _called_name(statement.value) == name
    ]
    assert len(matches) == 1
    return matches[0]


def _execute(statements, namespace):
    module = ast.Module(body=statements, type_ignores=[])
    exec(compile(module, str(OJ_PATH), 'exec'), namespace)


def _logging_bootstrap_statements():
    install_lineno = _top_level_call('install_flask_observability').lineno
    return [
        statement
        for statement in _tree().body
        if isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Call)
        and _called_name(statement.value) in {'setdefault', 'configure_logging'}
        and statement.lineno < install_lineno
    ]


def test_importing_oj_does_not_run_recovery_or_scheduling_jobs():
    tree = ast.parse((ROOT / 'oj.py').read_text(encoding='utf-8'))
    forbidden_top_level_calls = {
        'seed_elo_matchmaker_tick',
        'requeue_pending_on_startup',
        'seed_pending_requeue_watchdog',
        'seed_agent_judge_paused_probe',
        'seed_class_activity_refresh',
    }
    actual = set()
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for node in ast.walk(statement):
            if isinstance(node, ast.Call):
                name = _called_name(node)
                if name in forbidden_top_level_calls:
                    actual.add(name)

    assert actual == set()


def test_vibehub_reaper_only_starts_inside_web_service_guard():
    tree = _tree()
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _called_name(node) == 'ensure_vibehub_runtime_reaper'
    ]
    main_guard = next(
        statement
        for statement in tree.body
        if isinstance(statement, ast.If)
        and "__name__ == '__main__'" in ast.unparse(statement.test)
    )

    assert len(calls) == 1
    assert main_guard.lineno <= calls[0].lineno <= main_guard.end_lineno


def test_vibehub_storage_gc_only_starts_inside_web_service_guard():
    tree = _tree()
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _called_name(node) == 'ensure_vibehub_storage_gc'
    ]
    main_guard = next(
        statement
        for statement in tree.body
        if isinstance(statement, ast.If)
        and "__name__ == '__main__'" in ast.unparse(statement.test)
    )

    assert len(calls) == 1
    assert main_guard.lineno <= calls[0].lineno <= main_guard.end_lineno


def test_production_web_uses_central_gunicorn_config_without_schema_side_effects():
    config = (ROOT / 'deploy' / 'supervisor' / 'web.conf').read_text(encoding='utf-8')

    gunicorn_position = config.index('-m gunicorn')

    assert gunicorn_position >= 0
    assert 'scripts/init_db_schema.py' not in config
    assert '--config deploy/gunicorn.py' in config
    assert 'scripts/run_startup_jobs.py' not in config
    assert '--workers' not in config
    assert '--threads' not in config
    assert not (ROOT / 'scripts' / 'run_startup_jobs.py').exists()
    assert (ROOT / 'scripts' / 'recover_pending_tasks.py').exists()


def test_destructive_recovery_is_separate_from_safe_scheduler_bootstrap():
    tree = ast.parse((ROOT / 'oj.py').read_text(encoding='utf-8'))
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    safe_calls = {
        _called_name(node)
        for node in ast.walk(functions['ensure_background_schedulers'])
        if isinstance(node, ast.Call)
    }
    recovery_calls = {
        _called_name(node)
        for node in ast.walk(functions['recover_pending_after_all_workers_stopped'])
        if isinstance(node, ast.Call)
    }

    assert 'requeue_pending_on_startup' not in safe_calls
    assert 'requeue_pending_on_startup' in recovery_calls
    assert 'seed_class_activity_refresh' in safe_calls
    assert 'seed_class_activity_refresh' in recovery_calls


def test_pending_watchdog_also_reclaims_expired_repository_upload_staging():
    source = (
        ROOT / "oj_modules" / "runtime" / "pending_recovery.py"
    ).read_text(encoding="utf-8")

    register_start = source.index("def register_pending_requeue_watchdog_task")
    seed_start = source.index("def seed_pending_requeue_watchdog", register_start)
    watchdog = source[register_start:seed_start]

    assert "_cleanup_repository_upload_staging()" in watchdog
    assert "'repository_upload_cleanup': repository_upload_cleanup" in watchdog


def test_repository_domain_modules_live_in_the_repository_package():
    modules_root = ROOT / "oj_modules"
    package_root = modules_root / "repository"

    assert not list(modules_root.glob("repository_*.py"))
    assert {
        path.name
        for path in package_root.glob("*.py")
    } >= {
        "__init__.py",
        "admin.py",
        "includes.py",
        "index.py",
        "storage.py",
        "tree.py",
        "workspace.py",
    }


def test_gunicorn_config_preserves_single_worker_and_sse_capacity():
    settings = runpy.run_path(str(ROOT / 'deploy' / 'gunicorn.py'))

    assert settings['worker_class'] == 'gthread'
    assert settings['workers'] == 1
    assert settings['threads'] == 256
    assert settings['worker_connections'] == 1024
    assert settings['backlog'] == 512
    assert settings['sse_max_connections'] == 192
    assert settings['MIN_ORDINARY_REQUEST_SLOTS'] == 64
    assert settings['worker_connections'] >= settings['threads']
    assert (
        min(settings['threads'], settings['worker_connections'])
        - settings['sse_max_connections']
        >= settings['MIN_ORDINARY_REQUEST_SLOTS']
    )
    assert settings['keepalive'] == 5
    assert settings['worker_tmp_dir'] == '/dev/shm'
    assert settings['max_requests'] == 0
    assert settings['max_requests_jitter'] == 0
    assert settings['accesslog'] is None
    assert settings['errorlog'] == '-'


def test_gunicorn_rejects_sse_limit_that_consumes_every_thread(monkeypatch):
    monkeypatch.setattr(app_config, 'WEB_GUNICORN_THREADS', 128)
    monkeypatch.setattr(app_config, 'WEB_SSE_MAX_CONNECTIONS', 128)

    with pytest.raises(
        RuntimeError,
        match='WEB_SSE_MAX_CONNECTIONS 必须在 1–64 之间',
    ):
        runpy.run_path(str(ROOT / 'deploy' / 'gunicorn.py'))


def test_gunicorn_rejects_connection_limit_below_thread_count(monkeypatch):
    monkeypatch.setattr(app_config, 'WEB_GUNICORN_THREADS', 512)
    monkeypatch.setattr(app_config, 'WEB_GUNICORN_CONNECTIONS', 256)

    with pytest.raises(
        RuntimeError,
        match=(
            'WEB_GUNICORN_CONNECTIONS 必须大于等于 '
            'WEB_GUNICORN_THREADS（512）'
        ),
    ):
        runpy.run_path(str(ROOT / 'deploy' / 'gunicorn.py'))


def test_gunicorn_sse_limit_preserves_explicit_ordinary_request_slots(monkeypatch):
    monkeypatch.setattr(app_config, 'WEB_GUNICORN_THREADS', 128)
    monkeypatch.setattr(app_config, 'WEB_GUNICORN_CONNECTIONS', 256)
    monkeypatch.setattr(app_config, 'WEB_SSE_MAX_CONNECTIONS', 65)

    with pytest.raises(
        RuntimeError,
        match='WEB_SSE_MAX_CONNECTIONS 必须在 1–64 之间',
    ):
        runpy.run_path(str(ROOT / 'deploy' / 'gunicorn.py'))

    monkeypatch.setattr(app_config, 'WEB_SSE_MAX_CONNECTIONS', 64)
    settings = runpy.run_path(str(ROOT / 'deploy' / 'gunicorn.py'))
    assert settings['sse_max_connections'] == 64
    assert settings['sse_capacity'] == 64


def _static_cache_app():
    handler = next(
        node
        for node in _tree().body
        if isinstance(node, ast.FunctionDef)
        and node.name == '_set_security_headers'
    )
    app = PrecompressedStaticFlask(
        __name__,
        static_folder=str(ROOT / 'static'),
        static_url_path='/static',
    )

    @app.get('/download')
    def download():
        return send_from_directory(
            ROOT / 'static' / 'app',
            'layout.js',
            conditional=True,
        )

    _execute(
        [handler],
        {
            '_CONTENT_SECURITY_POLICY': '',
            'app': app,
            'request': request,
        },
    )
    return app


def _assert_static_revalidates(response):
    assert response.cache_control.public
    assert response.cache_control.no_cache
    assert response.cache_control.max_age == 0
    assert response.cache_control.must_revalidate
    assert not response.cache_control.immutable


def test_static_cache_contract_uses_revalidation_without_global_send_file_cache():
    handler = next(
        node
        for node in _tree().body
        if isinstance(node, ast.FunctionDef)
        and node.name == '_set_security_headers'
    )
    source = ast.unparse(handler)

    assert "request.endpoint == 'static'" in source
    assert 'resp.status_code in {200, 206, 304}' in source
    assert 'resp.cache_control.no_cache = True' in source
    assert 'resp.cache_control.max_age = 0' in source
    assert 'resp.cache_control.must_revalidate = True' in source
    assert 'resp.cache_control.immutable = None' in source
    assert "app.config['SEND_FILE_MAX_AGE_DEFAULT']" not in source
    assert 'STATIC_CACHE_MAX_AGE_SECONDS' not in OJ_PATH.read_text(encoding='utf-8')


def test_real_unfingerprinted_static_responses_revalidate_on_get_head_and_304():
    client = _static_cache_app().test_client()

    initial = client.get(
        '/static/app/layout.js',
        headers={'Accept-Encoding': 'identity'},
    )
    head = client.head(
        '/static/vendor/monaco/editor.js',
        headers={'Accept-Encoding': 'identity'},
    )
    not_modified = client.get(
        '/static/app/layout.js',
        headers={
            'Accept-Encoding': 'identity',
            'If-None-Match': initial.headers['ETag'],
        },
    )

    assert initial.status_code == 200
    assert head.status_code == 200
    assert head.data == b''
    assert not_modified.status_code == 304
    assert not_modified.headers['ETag'] == initial.headers['ETag']
    for response in (initial, head, not_modified):
        _assert_static_revalidates(response)


def test_static_cache_policy_skips_404_and_non_static_send_file_response():
    client = _static_cache_app().test_client()

    missing = client.get('/static/not-found.js')
    download = client.get('/download')

    assert missing.status_code == 404
    assert not missing.cache_control.public
    assert not missing.cache_control.must_revalidate
    assert download.status_code == 200
    assert not download.cache_control.public
    assert not download.cache_control.must_revalidate
    assert download.cache_control.max_age is None


def test_mysql_pool_exhaustion_has_template_free_retryable_503_handler():
    response_builder = next(
        node
        for node in _tree().body
        if isinstance(node, ast.FunctionDef)
        and node.name == '_mysql_pool_exhausted_response'
    )
    handler = next(
        node
        for node in _tree().body
        if isinstance(node, ast.FunctionDef)
        and node.name == '_handle_mysql_pool_exhausted'
    )
    source = ast.unparse(response_builder)

    assert any(
        ast.unparse(decorator) == 'app.errorhandler(MySQLPoolExhausted)'
        for decorator in handler.decorator_list
    )
    assert 'Response(' in source
    assert 'status=503' in source
    assert "response.headers['Retry-After'] = '1'" in source
    assert 'render_template(' not in source


def test_mysql_pool_tracking_wraps_auth_and_backpressure_precedes_headers():
    functions = {
        node.name: node
        for node in _tree().body
        if isinstance(node, ast.FunctionDef)
    }

    assert (
        functions['_begin_mysql_pool_exhaustion_request_scope'].lineno
        < _top_level_call('install_global_login_guard').lineno
    )
    # Flask 逆序执行 after_request；后注册的背压转换先生成最终响应，随后
    # 安全头处理器才能把 CSP 等头写到替换后的 503 上。
    assert (
        functions['_enforce_mysql_pool_exhaustion_backpressure'].lineno
        > functions['_set_security_headers'].lineno
    )


def test_template_globals_never_wait_behind_an_inflight_config_read():
    processor = next(
        node
        for node in _tree().body
        if isinstance(node, ast.FunctionDef) and node.name == 'inject_globals'
    )
    source = ast.unparse(processor)

    assert 'is_class_adjust_enabled(wait_timeout_seconds=0.0)' in source
    assert 'get_mail_settings(wait_timeout_seconds=0.0)' in source


def _mysql_pool_exhaustion_handler():
    response_builder = next(
        node
        for node in _tree().body
        if isinstance(node, ast.FunctionDef)
        and node.name == '_mysql_pool_exhausted_response'
    )
    handler = next(
        node
        for node in _tree().body
        if isinstance(node, ast.FunctionDef)
        and node.name == '_handle_mysql_pool_exhausted'
    )
    app = Flask(__name__)
    namespace = {
        'MySQLPoolExhausted': MySQLPoolExhausted,
        'Response': Response,
        'is_api_request': is_api_request,
        'app': app,
        'jsonify': jsonify,
        'request': request,
    }
    _execute([response_builder, handler], namespace)
    return app, namespace['_handle_mysql_pool_exhausted']


def _mysql_pool_backpressure_app():
    names = {
        '_begin_mysql_pool_exhaustion_request_scope',
        '_end_mysql_pool_exhaustion_request_scope',
        '_mysql_pool_exhausted_response',
        '_handle_mysql_pool_exhausted',
        '_enforce_mysql_pool_exhaustion_backpressure',
    }
    statements = [
        node
        for node in _tree().body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    assert {node.name for node in statements} == names

    app = Flask(__name__)
    namespace = {
        'MySQLPoolExhausted': MySQLPoolExhausted,
        'Response': Response,
        'app': app,
        'begin_mysql_pool_exhaustion_tracking': (
            begin_mysql_pool_exhaustion_tracking
        ),
        'current_mysql_pool_exhaustion': current_mysql_pool_exhaustion,
        'end_mysql_pool_exhaustion_tracking': end_mysql_pool_exhaustion_tracking,
        '_flask_request_ctx': _flask_request_ctx,
        'is_api_request': is_api_request,
        'jsonify': jsonify,
        'request': request,
    }
    _execute(statements, namespace)
    return app


@pytest.mark.parametrize(
    ('path', 'request_kwargs'),
    (
        ('/api', {'headers': {'Accept': '*/*'}}),
        ('/api/', {'headers': {'Accept': '*/*'}}),
        ('/api/problems/7?class_en=C1', {'headers': {'Accept': '*/*'}}),
        ('/private', {'json': {}}),
        ('/private', {'headers': {'X-Requested-With': 'XMLHttpRequest'}}),
        ('/private', {'headers': {'Accept': 'application/json'}}),
    ),
)
def test_mysql_pool_exhaustion_returns_json_for_api_and_json_requests(
    path,
    request_kwargs,
):
    app, handler = _mysql_pool_exhaustion_handler()
    with app.test_request_context(path, **request_kwargs):
        response = handler(MySQLPoolExhausted(1040, 'pool busy'))

    assert response.status_code == 503
    assert response.mimetype == 'application/json'
    assert response.get_json() == {
        'success': False,
        'message': '服务器繁忙，请稍后重试',
    }
    assert response.headers['Retry-After'] == '1'


@pytest.mark.parametrize(
    ('path', 'accept'),
    (
        ('/private', '*/*'),
        ('/private', 'text/html'),
        ('/api-like-but-not-api', '*/*'),
    ),
)
def test_mysql_pool_exhaustion_keeps_non_api_html_requests_as_plain_text(
    path,
    accept,
):
    app, handler = _mysql_pool_exhaustion_handler()
    with app.test_request_context(path, headers={'Accept': accept}):
        response = handler(MySQLPoolExhausted(1040, 'pool busy'))

    assert response.status_code == 503
    assert response.mimetype == 'text/plain'
    assert response.get_data(as_text=True) == '服务器繁忙，请稍后重试'
    assert response.headers['Retry-After'] == '1'


def test_route_local_database_catch_is_rewritten_to_retryable_json_503():
    app = _mysql_pool_backpressure_app()

    @app.get('/api/caught')
    def caught():
        try:
            raise MySQLPoolExhausted(1040, 'pool busy')
        except pymysql.Error:
            return jsonify(success=False, message='数据库操作失败'), 500

    response = app.test_client().get('/api/caught')

    assert response.status_code == 503
    assert response.get_json() == {
        'success': False,
        'message': '服务器繁忙，请稍后重试',
    }
    assert response.headers['Retry-After'] == '1'


def test_pool_backpressure_preserves_successful_fallback_and_request_isolation():
    app = _mysql_pool_backpressure_app()

    @app.get('/api/fallback')
    def fallback():
        try:
            raise MySQLPoolExhausted(1040, 'pool busy')
        except pymysql.Error:
            return jsonify(success=True, optional_rows=[])

    @app.get('/api/ok')
    def ok():
        return jsonify(success=True)

    client = app.test_client()
    fallback_response = client.get('/api/fallback')
    next_response = client.get('/api/ok')

    assert fallback_response.status_code == 200
    assert fallback_response.get_json() == {
        'success': True,
        'optional_rows': [],
    }
    assert next_response.status_code == 200
    assert next_response.get_json() == {'success': True}


def test_pool_backpressure_keeps_existing_structured_503_response():
    app = _mysql_pool_backpressure_app()

    @app.get('/health/ready')
    def ready():
        try:
            raise MySQLPoolExhausted(1040, 'pool busy')
        except pymysql.Error:
            return jsonify(status='unhealthy', mysql=False, redis=True), 503

    response = app.test_client().get('/health/ready')

    assert response.status_code == 503
    assert response.get_json() == {
        'status': 'unhealthy',
        'mysql': False,
        'redis': True,
    }
    assert response.headers['Retry-After'] == '1'


def test_pool_backpressure_request_scopes_restore_across_nested_contexts():
    app = _mysql_pool_backpressure_app()

    with app.test_request_context('/api/outer'):
        app.preprocess_request()
        outer_error = MySQLPoolExhausted(1040, 'outer request')
        assert current_mysql_pool_exhaustion() is outer_error

        with app.test_request_context('/api/inner'):
            app.preprocess_request()
            assert current_mysql_pool_exhaustion() is None
            inner_error = MySQLPoolExhausted(1040, 'inner request')
            assert current_mysql_pool_exhaustion() is inner_error

        assert current_mysql_pool_exhaustion() is outer_error

    assert current_mysql_pool_exhaustion() is None


def test_pool_scope_survives_synchronous_copied_request_context():
    app = _mysql_pool_backpressure_app()

    @app.get('/api/copied-sync')
    def copied_sync():
        @copy_current_request_context
        def copied_operation():
            return current_mysql_pool_exhaustion()

        assert copied_operation() is None
        try:
            raise MySQLPoolExhausted(1040, 'outer request remains tracked')
        except pymysql.Error:
            return jsonify(success=False), 500

    response = app.test_client().get('/api/copied-sync')

    assert response.status_code == 503
    assert response.headers['Retry-After'] == '1'


def test_copied_request_context_thread_cannot_reset_parent_scope():
    app = _mysql_pool_backpressure_app()
    worker_errors = []
    worker_tracking = []

    @app.get('/api/copied-thread')
    def copied_thread():
        @copy_current_request_context
        def copied_operation():
            MySQLPoolExhausted(1040, 'worker request')
            worker_tracking.append(current_mysql_pool_exhaustion())

        def run():
            try:
                copied_operation()
            except BaseException as exc:  # teardown token 错位也必须被观测到
                worker_errors.append(exc)

        worker = threading.Thread(target=run)
        worker.start()
        worker.join()
        return jsonify(success=True)

    response = app.test_client().get('/api/copied-thread')

    assert response.status_code == 200
    assert worker_errors == []
    assert worker_tracking == [None]
    MySQLPoolExhausted(1040, 'after copied request')
    assert current_mysql_pool_exhaustion() is None


def test_gunicorn_worker_only_ensures_safe_schedulers_after_import(monkeypatch):
    settings = runpy.run_path(str(ROOT / 'deploy' / 'gunicorn.py'))
    calls = []
    fake_oj = types.ModuleType('oj')
    fake_oj.ensure_background_schedulers = lambda: calls.append('schedulers')
    fake_oj.ensure_vibehub_runtime_reaper = lambda: calls.append('vibehub-reaper')
    fake_oj.ensure_vibehub_storage_gc = lambda: calls.append('vibehub-storage-gc')
    monkeypatch.setitem(sys.modules, 'oj', fake_oj)

    logged = []
    worker = types.SimpleNamespace(
        log=types.SimpleNamespace(info=lambda message: logged.append(message)),
    )
    settings['post_worker_init'](worker)

    assert calls == ['vibehub-reaper', 'vibehub-storage-gc', 'schedulers']
    assert logged == [
        'Ensuring VibeHub reapers and NumericalOJ background schedulers in the Web worker'
    ]


def test_supervisors_keep_distinct_runtime_controls_and_project_local_logs():
    configs = {
        name: (ROOT / 'deploy' / 'supervisor' / f'{name}.conf').read_text(
            encoding='utf-8',
        )
        for name in ('web', 'celery', 'observability')
    }

    pidfiles = set()
    sockets = set()
    for name, config in configs.items():
        assert f'pidfile=/tmp/noj_{name}_supervisord.pid' in config
        assert f'file=/tmp/noj_{name}_supervisor.sock' in config
        assert 'logfile=%(here)s/../../logs/supervisor/' in config
        assert 'stdout_logfile=%(here)s/../../logs/services/' in config
        assert 'childlogdir=%(here)s/../../logs/services' in config
        assert 'umask=0077' in config
        assert '/tmp/' not in '\n'.join(
            line for line in config.splitlines() if 'logfile=' in line
        )
        pidfiles.add(
            next(line for line in config.splitlines() if line.startswith('pidfile='))
        )
        sockets.add(
            next(line for line in config.splitlines() if line.startswith('file='))
        )

    assert len(pidfiles) == len(configs)
    assert len(sockets) == len(configs)

    web_parser = configparser.RawConfigParser()
    web_parser.read(ROOT / 'deploy' / 'supervisor' / 'web.conf', encoding='utf-8')
    assert web_parser.getint('supervisord', 'minfds') == 8192


def test_local_development_supervisor_also_uses_project_local_logs():
    config = (ROOT / 'deploy' / 'supervisor' / 'local-dev.conf').read_text(
        encoding='utf-8',
    )
    logfile_lines = [
        line for line in config.splitlines() if 'logfile=' in line
    ]

    assert 'logfile=%(here)s/../../logs/supervisor/local-dev.log' in config
    assert 'childlogdir=%(here)s/../../logs/services' in config
    assert logfile_lines
    assert all('%(here)s/../../logs/' in line for line in logfile_lines)
    assert '/tmp/' not in '\n'.join(logfile_lines)


def test_agent_workers_start_with_safe_autoscale_and_one_prefetched_message():
    for filename in ('celery.conf', 'local-dev.conf'):
        parser = configparser.RawConfigParser()
        parser.read(
            ROOT / 'deploy' / 'supervisor' / filename,
            encoding='utf-8',
        )
        command = parser.get('program:celery_agent', 'command')
        assert '-Q agent --autoscale=1,1 --prefetch-multiplier=1' in command
        assert ' -c 1 ' not in command


def test_agent_worker_dynamic_concurrency_is_installed_at_composition_root():
    install = _top_level_call('install_agent_concurrency_control')
    configure = _top_level_call('configure_agent_concurrency_runtime_applier')

    assert install.lineno < configure.lineno
    assert 'apply_agent_concurrency_limit(celery, limit)' in ast.unparse(configure)


def test_late_ack_uses_a_visibility_window_suitable_for_agent_tasks():
    source = OJ_PATH.read_text(encoding='utf-8')

    assert '_CELERY_REDIS_VISIBILITY_TIMEOUT_SECONDS = 6 * 60 * 60' in source
    assert "'visibility_timeout': _CELERY_REDIS_VISIBILITY_TIMEOUT_SECONDS" in source


def test_business_processes_preserve_container_readable_file_modes():
    expected_programs = {
        'web.conf': ('program:web',),
        'celery.conf': (
            'program:celery_judge',
            'program:celery_agent',
            'program:celery_agent_judge',
        ),
        'local-dev.conf': (
            'program:web',
            'program:celery_judge',
            'program:celery_agent',
            'program:celery_agent_judge',
        ),
    }

    for filename, programs in expected_programs.items():
        parser = configparser.RawConfigParser()
        parser.read(ROOT / 'deploy' / 'supervisor' / filename, encoding='utf-8')

        assert parser.get('supervisord', 'umask') == '0077'
        for program in programs:
            assert parser.get(program, 'umask') == '0022'

    observability = configparser.RawConfigParser()
    observability.read(
        ROOT / 'deploy' / 'supervisor' / 'observability.conf',
        encoding='utf-8',
    )
    assert observability.get('supervisord', 'umask') == '0077'
    assert not observability.has_option('program:log_collector', 'umask')


def test_logging_bootstrap_sets_web_service_and_configures_once(monkeypatch):
    import os

    configure_logging = MagicMock()
    monkeypatch.delenv('NUMOJ_SERVICE_NAME', raising=False)
    _execute(
        _logging_bootstrap_statements(),
        {
            'os': os,
            '_cfg': SimpleNamespace(LOG_LEVEL='DEBUG'),
            'configure_logging': configure_logging,
        },
    )

    assert os.environ['NUMOJ_SERVICE_NAME'] == 'web'
    configure_logging.assert_called_once_with(level='DEBUG')


def test_logging_bootstrap_preserves_worker_service_name(monkeypatch):
    import os

    configure_logging = MagicMock()
    monkeypatch.setenv('NUMOJ_SERVICE_NAME', 'worker-judge')
    _execute(
        _logging_bootstrap_statements(),
        {
            'os': os,
            '_cfg': SimpleNamespace(LOG_LEVEL='WARNING'),
            'configure_logging': configure_logging,
        },
    )

    assert os.environ['NUMOJ_SERVICE_NAME'] == 'worker-judge'
    configure_logging.assert_called_once_with(level='WARNING')


def test_logging_bootstrap_precedes_all_business_module_imports():
    tree = _tree()
    observability_import = next(
        node
        for node in tree.body
        if isinstance(node, ast.ImportFrom)
        and node.module == 'oj_modules.observability'
    )
    first_business_import = next(
        node
        for node in tree.body
            if isinstance(node, ast.ImportFrom)
            and node.module
            and node.module.startswith('oj_modules.')
            and node.module not in {
                'oj_modules.config',
                'oj_modules.observability',
            }
        )
    bootstrap = _logging_bootstrap_statements()

    assert len(bootstrap) == 2
    assert observability_import.lineno < bootstrap[0].lineno
    assert bootstrap[0].lineno < bootstrap[1].lineno < first_business_import.lineno


def test_flask_observability_is_installed_once_with_proxy_config():
    app = object()
    install = MagicMock()
    _execute(
        [_top_level_call('install_flask_observability')],
        {
            'app': app,
            '_cfg': SimpleNamespace(
                LOG_TRUSTED_PROXY_CIDRS=['10.0.0.0/8', '2001:db8::/32'],
            ),
            'install_flask_observability': install,
        },
    )

    install.assert_called_once_with(
        app,
        trusted_proxy_cidrs=['10.0.0.0/8', '2001:db8::/32'],
    )


def test_celery_observability_is_installed_once_with_log_level():
    celery = object()
    install = MagicMock()
    _execute(
        [_top_level_call('install_celery_observability')],
        {
            'celery': celery,
            '_cfg': SimpleNamespace(LOG_LEVEL='ERROR'),
            'install_celery_observability': install,
        },
    )

    install.assert_called_once_with(celery, level='ERROR')
