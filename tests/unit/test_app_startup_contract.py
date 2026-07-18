import ast
from pathlib import Path


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


def test_production_web_runs_schema_and_recovery_before_gunicorn():
    config = (ROOT / 'web.conf').read_text(encoding='utf-8')

    schema_position = config.index('scripts/init_db_schema.py')
    recovery_position = config.index('scripts/run_startup_jobs.py')
    gunicorn_position = config.index('-m gunicorn')

    assert schema_position < recovery_position < gunicorn_position


def test_web_and_celery_supervisors_do_not_share_pid_or_log_files():
    web_config = (ROOT / 'web.conf').read_text(encoding='utf-8')
    celery_config = (ROOT / 'celery.conf').read_text(encoding='utf-8')

    assert 'pidfile=/tmp/noj_web_supervisord.pid' in web_config
    assert 'pidfile=/tmp/noj_celery_supervisord.pid' in celery_config
    assert 'logfile=/tmp/noj_web_supervisord.log' in web_config
    assert 'logfile=/tmp/noj_celery_supervisord.log' in celery_config
