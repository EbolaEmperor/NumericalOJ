import ast
from pathlib import Path
import runpy
import sys
import types


ROOT = Path(__file__).resolve().parents[2]


def _called_name(node):
    function = node.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        return function.attr
    return None


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


def test_production_web_runs_schema_then_uses_central_gunicorn_config():
    config = (ROOT / 'web.conf').read_text(encoding='utf-8')

    schema_position = config.index('scripts/init_db_schema.py')
    gunicorn_position = config.index('-m gunicorn')

    assert schema_position < gunicorn_position
    assert '--config gunicorn.conf.py' in config
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


def test_gunicorn_config_preserves_single_worker_and_sse_capacity():
    settings = runpy.run_path(str(ROOT / 'gunicorn.conf.py'))

    assert settings['worker_class'] == 'gthread'
    assert settings['workers'] == 1
    assert settings['threads'] == 64
    assert settings['max_requests'] == 0
    assert settings['max_requests_jitter'] == 0


def test_gunicorn_worker_only_ensures_safe_schedulers_after_import(monkeypatch):
    settings = runpy.run_path(str(ROOT / 'gunicorn.conf.py'))
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


def test_web_and_celery_supervisors_do_not_share_pid_or_log_files():
    web_config = (ROOT / 'web.conf').read_text(encoding='utf-8')
    celery_config = (ROOT / 'celery.conf').read_text(encoding='utf-8')

    assert 'pidfile=/tmp/noj_web_supervisord.pid' in web_config
    assert 'pidfile=/tmp/noj_celery_supervisord.pid' in celery_config
    assert 'logfile=/tmp/noj_web_supervisord.log' in web_config
    assert 'logfile=/tmp/noj_celery_supervisord.log' in celery_config
