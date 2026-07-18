from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def _read(path):
    return (ROOT / path).read_text(encoding='utf-8')


def test_deploy_shells_are_syntactically_valid():
    subprocess.run(
        ['bash', '-n', 'deploy.sh', 'deploy/remote.sh', 'deploy/shell_helpers.sh'],
        cwd=ROOT,
        check=True,
    )


def test_local_deploy_entry_enforces_known_commit_and_production_target():
    script = _read('deploy.sh')

    assert "git status --porcelain" in script
    assert "hostname -s" in script
    assert "'/home/ebola/oj'" in script
    assert "'computing'" in script
    assert "sys.version_info[:2] == (3, 12)" in script
    assert "id -un" in script
    assert 'docker info' in script
    assert 'deploy/remote.sh' in script
    assert 'pkill' not in script
    assert 'NUMOJ_DEPLOY_ROOT' not in script
    assert 'git archive --format=tar "$REVISION"' in script
    assert 'git ls-tree -rz --name-only "$REVISION"' in script
    assert '--from0 --files-from="$TRACKED_FILES"' in script
    assert 'install -m 0600' in script
    assert '--diff-filter=ACMR' in script
    assert 'git ls-tree -rz --name-only "$REVISION" -- static >"$STATIC_FILES"' in script
    assert '候选 staging 已存在，拒绝复用' in script
    assert 'install -m 0600 "$root/.env" "$staging/.env"' in script
    assert '--expected-previous-revision' in script
    assert 'deploy/manifest.py' in script
    assert 'NUMOJ_DEPLOY_MIN_TARGET_FREE_BYTES' in script
    assert 'NUMOJ_DEPLOY_MIN_STATE_FREE_BYTES' in script
    assert 'NUMOJ_DEPLOY_MIN_DOCKER_FREE_BYTES' in script


def test_deploy_preserves_production_owned_paths():
    excludes = set(_read('deploy/rsync-excludes.txt').splitlines())

    assert {'/config.py', '/static/', '/tmp/', '/uploads/', '/judger/',
            '/ranking_uploads/', '/competitions/'} <= excludes
    remote = _read('deploy/remote.sh')
    assert 'deploy/static_files.py' in remote
    assert 'classify' in remote
    assert 'remove-recorded' in remote
    assert '拒绝冲突或符号链接路径' in remote
    assert '生产 static 不接受仓库符号链接' in remote
    assert 'install -D' not in remote
    assert 'deploy/manifest.py' in remote
    assert 'deploy/managed_tree.py' in remote
    assert ' --exclude=config.py' not in remote
    assert 'config.py|.env|static/*' not in remote


def test_remote_deploy_orders_build_stop_backup_schema_and_health_checks():
    script = _read('deploy/remote.sh')

    positions = [
        script.index("phase='构建候选镜像'"),
        script.index("phase='停止现有服务'"),
        script.index("phase='备份数据库与当前代码'"),
        script.index("phase='激活候选代码'"),
        script.index("phase='同步数据库结构与恢复任务'"),
        script.index("phase='切换运行环境、镜像并启动服务'"),
        script.index("phase='健康检查'"),
        script.index("phase='记录部署状态'"),
    ]
    assert positions == sorted(positions)
    assert 'mysqldump' in script
    assert 'database_final' in script
    assert 'gzip -t "$database_partial"' in script
    assert 'tar -tzf "$backup_partial"' in script
    assert '--ignore-failed-read' not in script
    assert 'git -C "$TARGET" ls-files -z' in script
    assert 'trap - ERR' in script
    assert script.index('shutdown_started=1') < script.index(
        'stop_supervisor web "$STAGING/deploy/supervisor/web.conf"',
        script.index("phase='停止现有服务'"),
    )
    assert 'scripts/init_db_schema.py --dry-run' in script
    assert 'scripts/recover_pending_tasks.py --confirm-celery-stopped' in script
    assert '/health/live' in script
    assert '/health/ready' in script
    assert '--connect-timeout 2 --max-time 5' in script
    assert 'inspect active_queues' in script
    assert 'supervisorctl -c "$config" status' in script
    assert 'celery:celery_judge celery:celery_agent celery:celery_agent_judge' in script
    for node_name in ("f'judge@{host}'", "f'agent@{host}'", "f'agent_judge@{host}'"):
        assert node_name in script
    assert 'initial_web_present' in script
    assert 'initial_celery_present' in script
    assert 'verify_rollback_services "$initial_web_present" "$initial_celery_present"' in script
    assert "phase='停机前磁盘余量检查'" in script
    assert script.index("phase='停机前磁盘余量检查'") < script.index(
        "phase='停止现有服务'"
    )
    assert 'Docker data-root' in script
    assert 'numoj_require_free_bytes "$TARGET"' in script
    assert 'numoj_require_free_bytes "$STATE"' in script
    assert 'numoj_require_free_bytes "$DOCKER_ROOT"' in script


def test_production_supervisors_only_manage_processes():
    web = _read('deploy/supervisor/web.conf')
    celery = _read('deploy/supervisor/celery.conf')

    assert 'init_db_schema.py' not in web
    assert 'init_db_schema.py' not in celery
    assert '--config deploy/gunicorn.py' in web
    assert '/home/ebola/.numericaloj-deploy/current-venv/bin/python3 -m gunicorn' in web
    for node_name in ('judge@%%h', 'agent@%%h', 'agent_judge@%%h'):
        assert node_name in celery
    assert celery.count(
        '/home/ebola/.numericaloj-deploy/current-venv/bin/python3 -m celery'
    ) == 3
    assert celery.count('stopwaitsecs=1900') == 3
    assert '[unix_http_server]' in web
    assert '[unix_http_server]' in celery


def test_celery_health_names_match_supervisor_group_namespecs():
    from supervisor.options import ServerOptions

    options = ServerOptions()
    options.configfile = str(ROOT / 'deploy/supervisor/celery.conf')
    options.process_config(False)
    group = next(group for group in options.process_group_configs if group.name == 'celery')
    namespecs = {f'{group.name}:{program.name}' for program in group.process_configs}

    assert namespecs == {
        'celery:celery_judge',
        'celery:celery_agent',
        'celery:celery_agent_judge',
    }
    remote = _read('deploy/remote.sh')
    assert 'celery:celery_judge celery:celery_agent celery:celery_agent_judge' in remote


def test_root_configuration_files_are_grouped_by_responsibility():
    old_root_files = (
        'web.conf',
        'celery.conf',
        'local_dev.conf',
        'gunicorn.conf.py',
        'myojdb.sql',
        'requirements.txt',
        'requirements-test.txt',
        'requirements-optional.txt',
        'cm_problems.json',
        'initial_review.md',
        'fix-tools',
    )
    assert not any((ROOT / name).exists() for name in old_root_files)

    expected = (
        'deploy/gunicorn.py',
        'deploy/supervisor/web.conf',
        'deploy/supervisor/celery.conf',
        'deploy/supervisor/local-dev.conf',
        'database/bootstrap.sql',
        'requirements/production.txt',
        'requirements/test.txt',
        'requirements/optional.txt',
    )
    assert all((ROOT / name).is_file() for name in expected)


def test_remote_deploy_has_fail_closed_process_and_atomic_state_guards():
    script = _read('deploy/remote.sh')

    assert 'deploy/process_guard.py' in script
    assert 'resolve_supervisor_pid' in script
    assert 'guard_pid supervisor "$kind" "$pid"' in script
    assert 'terminate_app_processes "$kind"' in script
    assert 'signal_guarded_process' in script
    assert 'kill -TERM "$pid"' not in script
    assert 'kill -KILL "$pid"' not in script
    assert 'STATIC_ADDITIONS' in script
    assert 'STATIC_INSTALLED' in script
    assert script.index("phase='静态资源预检'") < script.index("phase='停止现有服务'")
    assert 'requirements/production.txt' in script
    assert 'python3 -m venv' in script
    assert '-m pip check' in script
    assert 'current-venv' in script
    assert 'REQUIREMENTS_SHA256' in script
    assert 'py312-$REQUIREMENTS_SHA256' in script
    assert 'deploy/venv_integrity.py' in script
    assert '"${VENV_TOOL[@]}" verify' in script
    assert '.numericaloj-revision' not in script
    assert '"$RUN_STATE/requirements-sha256"' in script
    assert 'numoj_atomic_symlink "runs/$RUN_ID" "$STATE/current" "$RUN_ID"' in script
    assert 'trap cleanup_on_exit EXIT' in script
    assert 'state_judger_id' in script
    assert 'state_agent_judge_id' in script
    assert '部署基线在本地预检后已变化' in script
    assert 'authoritative_previous_revision' in script
    assert '>"$STATE/current_commit"' not in script
    assert '"${MANAGED_TOOL[@]}" backup' in script
    assert '"${MANAGED_TOOL[@]}" activate' in script
    assert '"${MANAGED_TOOL[@]}" rollback' in script
    assert 'rsync -a \\' not in script
    assert "'DB_EXISTS'" in script
