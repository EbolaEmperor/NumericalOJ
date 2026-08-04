import ast
import configparser
from pathlib import Path
import runpy
import sys
import types
from types import SimpleNamespace
from unittest.mock import MagicMock


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
    assert settings['threads'] == 64
    assert settings['max_requests'] == 0
    assert settings['max_requests_jitter'] == 0
    assert settings['accesslog'] is None
    assert settings['errorlog'] == '-'


def test_gunicorn_worker_only_ensures_safe_schedulers_after_import(monkeypatch):
    settings = runpy.run_path(str(ROOT / 'deploy' / 'gunicorn.py'))
    calls = []
    fake_oj = types.ModuleType('oj')
    fake_oj.ensure_background_schedulers = lambda: calls.append('ensure')
    monkeypatch.setitem(sys.modules, 'oj', fake_oj)

    logged = []
    worker = types.SimpleNamespace(
        log=types.SimpleNamespace(info=lambda message: logged.append(message)),
    )
    settings['post_worker_init'](worker)

    assert calls == ['ensure']
    assert logged == ['Ensuring NumericalOJ background schedulers in the Web worker']


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


def test_agent_workers_use_one_slot_and_one_prefetched_message():
    for filename in ('celery.conf', 'local-dev.conf'):
        parser = configparser.RawConfigParser()
        parser.read(
            ROOT / 'deploy' / 'supervisor' / filename,
            encoding='utf-8',
        )
        command = parser.get('program:celery_agent', 'command')
        assert '-Q agent -c 1 --prefetch-multiplier=1' in command


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
        and node.module != 'oj_modules.observability'
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
