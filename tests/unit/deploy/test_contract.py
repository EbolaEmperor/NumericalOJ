from pathlib import Path
import shutil
import subprocess

import pytest

from deploy import legacy_supervisor


ROOT = Path(__file__).resolve().parents[3]


def _read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def test_deploy_shell_is_syntactically_valid():
    subprocess.run(["bash", "-n", "deploy.sh"], cwd=ROOT, check=True)


def test_deploy_is_an_in_place_entry_without_environment_whitelists_or_tests():
    script = _read("deploy.sh")

    assert 'dirname -- "${BASH_SOURCE[0]}"' in script
    assert "cd \"$ROOT_DIR\"" in script
    for forbidden in (
        "why-server",
        "/home/ebola",
        "hostname",
        "id -un",
        "realpath",
        "ssh ",
        "rsync",
        "git status",
        "git rev-parse",
        "pytest",
        "tests/",
        "--dry-run",
        "/health/live",
        "/health/ready",
    ):
        assert forbidden not in script


def test_deploy_prepares_plan_then_backs_up_while_stopped_and_restarts_everything():
    script = _read("deploy.sh")
    phases = [
        "phase='初始化日志目录'",
        "phase='准备 Python 运行环境'",
        "phase='准备 ARC-AGI-3 公开游戏'",
        "phase='构建判题镜像'",
        "phase='准备判题器官方头文件工具链'",
        "phase='核验编辑器语言服务'",
        "phase='准备数据库备份计划'",
        "phase='确认现有服务可管理'",
        "phase='停止现有服务'",
        "phase='创建并验证数据库回滚点'",
        "phase='迁移等价多班级数据库结构'",
        "phase='切换运行环境并更新数据库结构'",
        "phase='切换判题镜像'",
        "phase='启动统一日志采集'",
        "phase='启动 Celery 服务'",
        "phase='启动 Web 服务'",
    ]

    positions = [script.index(phase) for phase in phases]
    assert positions == sorted(positions)
    assert (
        '"$JUDGER_STABLE" "$JUDGER_CANDIDATE" docker/judger' in script
    )
    assert (
        '"$AGENT_JUDGE_STABLE" "$AGENT_JUDGE_CANDIDATE" '
        "docker/agent_judge" in script
    )
    assert 'build_candidate_image' in script
    assert script.count('--label "$MANAGED_IMAGE_LABEL"') == 1
    assert "numericaloj-judger:deploy-*" in script
    assert "numericaloj-agent-judge:deploy-*" in script
    assert 'remove_stale_candidate_tags' in script
    assert 'docker image prune --force --filter "label=$MANAGED_IMAGE_LABEL"' in script
    assert "deploy/backup_database.py preflight" in script
    assert "deploy/backup_database.py backup" in script
    assert 'deploy/backup_database.py mark-success' in script
    assert 'deploy/backup_database.py prune' in script
    assert "scripts/migrate_remove_primary_class.py" in script
    assert "scripts/init_db_schema.py" in script
    assert (
        "cleanup-expired-uploads --apply --confirm-expired-staging-delete"
        in script
    )
    assert "scripts/repository_storage_admin.py doctor" in script
    assert "scripts/recover_pending_tasks.py --confirm-celery-stopped" in script
    for one_time_entry in (
        "m20260725_repository_index_generations.py",
        "m20260725_repository_tree_storage.py",
        "m20260725_forum_anonymous_identity_ownership.py",
        "scripts/backfill_class_logos.py",
    ):
        assert one_time_entry not in script
    arc_prepare = script.index("deploy/prepare_arc_agi_3.py")
    arc_switch = script.index(
        'mv -Tf -- "$ARC_CURRENT_SET_TEMP" "$ARC_CURRENT_SET"'
    )
    assert arc_prepare < script.index("phase='停止现有服务'")
    assert script.index("phase='创建并验证数据库回滚点'") < arc_switch
    assert "--expected-count 25" in script
    assert 'ARC_DATA_ROOT="$STATE_DIR/arc-agi-3"' in script
    assert (
        'EDITOR_TOOLCHAIN_ROOT="$STATE_DIR/editor-toolchains"' in script
    )
    assert (
        'CURRENT_EDITOR_TOOLCHAIN="$STATE_DIR/current-editor-toolchain"'
        in script
    )
    assert (
        'ln -s "editor-toolchains/$candidate_slot" '
        '"$CURRENT_EDITOR_TOOLCHAIN_TEMP"' in script
    )
    assert (
        'mv -Tf -- "$CURRENT_EDITOR_TOOLCHAIN_TEMP" '
        '"$CURRENT_EDITOR_TOOLCHAIN"' in script
    )
    assert 'docker tag "$JUDGER_CANDIDATE" "$JUDGER_STABLE"' in script
    assert (
        'docker tag "$AGENT_JUDGE_CANDIDATE" "$AGENT_JUDGE_STABLE"' in script
    )
    stop_phase = script.index("phase='停止现有服务'")
    celery_stop = script.index("  'Celery' celery", stop_phase)
    web_stop = script.index("  'Web' web", stop_phase)
    assert celery_stop < web_stop
    assert "CELERY_STOP_TIMEOUT_SECONDS=1960" in script
    assert script.index("phase='确认全部服务状态'") > script.index(
        "phase='启动 Web 服务'"
    )
    assert 'pkill' not in script
    assert script.index("phase='停止现有服务'") < script.index(
        "phase='创建并验证数据库回滚点'"
    ) < script.index("scripts/init_db_schema.py")
    schema_sync = script.index("scripts/init_db_schema.py")
    expired_upload_cleanup = script.index(
        "cleanup-expired-uploads --apply --confirm-expired-staging-delete"
    )
    repository_doctor = script.index(
        "scripts/repository_storage_admin.py doctor"
    )
    task_recovery = script.index("scripts/recover_pending_tasks.py")
    assert (
        schema_sync
        < expired_upload_cleanup
        < repository_doctor
        < task_recovery
    )


def test_deploy_detects_and_uses_daemon_docker_build_cache():
    script = _read("deploy.sh")

    assert 'DOCKER_BUILDER="${NUMOJ_DOCKER_BUILDER:-default}"' in script
    assert "JUDGER_STABLE='numericaloj-judger:latest'" in script
    assert "AGENT_JUDGE_STABLE='numericaloj-agent-judge:latest'" in script
    assert 'docker buildx inspect "$DOCKER_BUILDER"' in script
    assert "docker info --format '{{.DockerRootDir}}'" in script
    assert "docker buildx du" in script
    assert '--builder "$DOCKER_BUILDER"' in script
    assert "docker image inspect --format '{{.Id}}' \"$stable\"" in script
    assert "SOURCE_IMAGE_LABEL='org.numericaloj.source-sha256'" in script
    assert "docker_source_digest" in script
    assert "image_source_digest" in script
    assert 'if [[ "$stable_source_digest" == "$source_digest" ]]' in script
    assert 'docker tag "$stable" "$candidate"' in script
    assert '--label "$SOURCE_IMAGE_LABEL=$source_digest"' in script
    assert '--cache-from "$stable"' not in script
    assert "DOCKER_BUILDKIT=1 docker build" in script
    assert "--build-arg BUILDKIT_INLINE_CACHE=1" in script
    for marker in (
        "debian:bookworm-slim@sha256:60eac759",
        "node:20-bookworm@sha256:8f693eaa",
        "intel-oneapi-mkl-devel",
        "torch torchvision",
        "paddlepaddle paddleocr",
        "playwright install chromium",
    ):
        assert marker in script
    assert "为避免冷构建，拒绝继续部署" in script
    assert "本次将冷构建" not in script


def test_deploy_uses_bounded_project_local_runtime_state():
    script = _read("deploy.sh")

    assert 'STATE_DIR="$ROOT_DIR/.deploy"' in script
    assert "venvs/slot-a" in script
    assert "slot-b" in script
    assert 'mv -Tf -- "$CURRENT_VENV_TEMP" "$CURRENT_VENV"' in script
    assert "LOCK_FILE='/tmp/noj_deploy.lock'" in script
    assert 'exec 9>>"$LOCK_FILE"' in script
    assert '"$STATE_DIR/deploy.lock"' not in script
    assert "flock -n 9" in script
    assert script.count('"$CANDIDATE_SUPERVISORD" -c ') == 3
    assert script.count('"$CANDIDATE_SUPERVISORD" -c "$OBSERVABILITY_CONFIG" 9>&-') == 1
    assert script.count('"$CANDIDATE_SUPERVISORD" -c "$CELERY_CONFIG" 9>&-') == 1
    assert script.count('"$CANDIDATE_SUPERVISORD" -c "$WEB_CONFIG" 9>&-') == 1
    assert 'BACKUP_DIR="$STATE_DIR/backups"' in script
    assert 'install -d -m 0700 "$STATE_DIR" "$VENV_ROOT"' in script
    assert 'install -d -m 0700 "$STATE_DIR" "$VENV_ROOT" "$BACKUP_DIR"' not in script
    assert 'backup_plan="$BACKUP_DIR/plans/$RUN_ID.json"' in script
    assert (
        'backup_manifest="$BACKUP_DIR/manifests/$RUN_ID.manifest.json"'
        in script
    )
    orchestrator = _read("deploy/backup/orchestrator.py")
    assert 'f"{run_id}.json"' in orchestrator
    assert 'f"{run_id}.manifest.json"' in orchestrator


def test_deploy_preserves_failed_backup_and_only_prunes_after_stable_startup():
    script = _read("deploy.sh")

    cleanup = script.index("cleanup()")
    main = script.index("cd \"$ROOT_DIR\"")
    assert "deploy/backup_database.py mark-failed" in script[cleanup:main]

    confirmed = script.index("phase='确认全部服务状态'")
    mark_success = script.index("deploy/backup_database.py mark-success", confirmed)
    prune = script.index("deploy/backup_database.py prune", mark_success)
    assert confirmed < mark_success < prune
    restart_confirmed = script.index("restart_started=0", mark_success)
    assert mark_success < restart_confirmed < prune
    assert "--keep-success 2" in script[prune:]
    assert '--plan "$backup_plan"' in script[mark_success:prune]
    assert '--protect-run-id "$RUN_ID"' in script[prune:]
    assert "start_sudo_keepalive" in script
    assert "/usr/bin/sudo -n -v" in script
    assert "stop_sudo_keepalive" in script
    assert script.index("deploy/backup_database.py prune", mark_success) < script.index(
        "stop_sudo_keepalive", prune
    )


def test_deploy_tracks_sudo_keepalive_as_a_shell_job_without_signalling_its_pid():
    script = _read("deploy.sh")
    start = script.index("start_sudo_keepalive()")
    assertion = script.index("assert_sudo_keepalive()")
    cleanup = script.index("if (($#))")
    helpers = script[start:cleanup]
    stop_helper = script[script.index("stop_sudo_keepalive()"):start]

    assert 'SUDO_KEEPALIVE_STOP="$STATE_DIR/.sudo-keepalive-$RUN_ID.stop"' in script
    assert '/usr/bin/touch -- "$SUDO_KEEPALIVE_STOP"' in stop_helper
    assert 'wait "$sudo_keepalive_pid"' in stop_helper
    assert 'wait "$sudo_keepalive_pid" >/dev/null 2>&1 || true' in stop_helper
    assert "return 0" in stop_helper
    assert 'kill "$sudo_keepalive_pid"' not in stop_helper
    assert 'kill "$sudo_keepalive_pid"' not in helpers
    assert "jobs -pr" in script[assertion:cleanup]
    assert script.count("assert_sudo_keepalive '") == 3
    assert "assert_sudo_keepalive '停止 Celery'" in script
    assert "assert_sudo_keepalive 'Celery 停止完成'" in script
    assert "assert_sudo_keepalive '数据库备份'" in script


def test_deploy_uses_a_clean_strategy_query_after_interactive_preflight():
    script = _read("deploy.sh")
    phase = script.index("phase='准备数据库备份计划'")
    confirmation = script.index("phase='确认现有服务可管理'", phase)
    section = script[phase:confirmation]

    assert 'deploy/backup_database.py preflight \\\n' in section
    assert (
        'backup_strategy="$("$CANDIDATE_PYTHON" -B '
        "deploy/backup_database.py preflight"
        not in section
    )
    assert 'backup_strategy="$("$CANDIDATE_PYTHON" -B ' in section
    assert "deploy/backup_database.py strategy" in section
    assert section.index("deploy/backup_database.py preflight") < section.index(
        "deploy/backup_database.py strategy"
    )


def test_deploy_only_advertises_a_verified_backup_after_backup_succeeds():
    script = _read("deploy.sh")
    phase = script.index("phase='创建并验证数据库回滚点'")
    switch = script.index("phase='切换运行环境并更新数据库结构'", phase)
    section = script[phase:switch]

    command = section.index("deploy/backup_database.py backup")
    assignment = section.index('database_backup="$backup_manifest"')
    assert command < assignment
    assert "数据库备份失败清单（不可作为回滚点）" in script
    assert "已验证的部署前数据库备份清单" in script


def test_deploy_contracts_primary_class_only_after_stopped_verified_backup():
    script = _read("deploy.sh")

    stopped = script.index("phase='停止现有服务'")
    backup = script.index("phase='创建并验证数据库回滚点'", stopped)
    backup_command = script.index(
        "deploy/backup_database.py backup",
        backup,
    )
    backup_verified = script.index(
        'database_backup="$backup_manifest"',
        backup_command,
    )
    migration_phase = script.index(
        "phase='迁移等价多班级数据库结构'",
        backup_verified,
    )
    migration_command = script.index(
        "scripts/migrate_remove_primary_class.py",
        migration_phase,
    )
    runtime_switch = script.index(
        "phase='切换运行环境并更新数据库结构'",
        migration_command,
    )
    schema_sync = script.index("scripts/init_db_schema.py", migration_command)

    assert (
        stopped
        < backup
        < backup_command
        < backup_verified
        < migration_phase
        < migration_command
        < runtime_switch
        < schema_sync
    )
    migration_section = script[migration_phase:schema_sync]
    assert "assert_service_stopped 'Celery' celery" in migration_section
    assert "assert_service_stopped 'Web' web" in migration_section
    assert "--apply" in migration_section
    assert "--confirm-app-writers-stopped" in migration_section
    assert "--confirm-backup-verified" in migration_section


def test_deploy_initializes_and_best_effort_restarts_log_collector():
    script = _read("deploy.sh")

    init_position = script.index("phase='初始化日志目录'")
    config_check_position = script.index("phase='校验生产本地配置'")
    stop_phase_position = script.index("phase='停止现有服务'")
    stop_position = script.index(
        "\nstop_observability_best_effort\n",
        stop_phase_position,
    )
    switch_position = script.index("phase='切换运行环境并更新数据库结构'")
    start_position = script.index("phase='启动统一日志采集'")
    celery_position = script.index("phase='启动 Celery 服务'")

    assert init_position < config_check_position
    assert stop_phase_position < stop_position < switch_position
    assert switch_position < start_position < celery_position
    assert (
        '"$BOOTSTRAP_PYTHON" -B scripts/log_admin.py init >/dev/null'
        in script
    )
    assert (
        'if "$CANDIDATE_SUPERVISORD" -c "$OBSERVABILITY_CONFIG" 9>&-; then'
        in script
    )
    assert 'wait_for_programs "$OBSERVABILITY_CONFIG" 15' in script
    assert script.count('业务服务继续启动') == 2
    assert 'exit 1' not in script[start_position:celery_position]


def test_deploy_discovers_python_312_without_requiring_system_python3():
    script = _read("deploy.sh")

    assert '"$STATE_DIR/bootstrap-python/bin/python3.12"' in script
    assert "${NUMOJ_PYTHON:-}" in script
    assert "python3.12" in script
    assert 'BOOTSTRAP_PYTHON="$(resolve_bootstrap_python)"' in script
    assert '"$BOOTSTRAP_PYTHON" -m venv "$CANDIDATE_VENV"' in script
    assert 'python3 -m venv "$CANDIDATE_VENV"' not in script


def test_deploy_fails_closed_without_private_production_config():
    script = _read("deploy.sh")
    preflight = _read("deploy/preflight.py")

    config_check = script.index("phase='校验生产本地配置'")
    dependency_install = script.index("phase='准备 Python 运行环境'")
    image_build = script.index("phase='构建判题镜像'")
    backup_plan = script.index("phase='准备数据库备份计划'")
    database_backup = script.index("phase='创建并验证数据库回滚点'")
    assert config_check < dependency_install < image_build < backup_plan
    assert backup_plan < database_backup
    assert 'ENV_FILE="$ROOT_DIR/.env"' in script
    assert 'deploy/preflight.py validate-config "$ENV_FILE"' in script
    assert 'getattr(config, "ENV_FILE_LOADED", False)' in preflight
    assert 'getattr(config, "ENV_FILE_KEYS", ())' in preflight
    assert "metadata.st_uid != os.geteuid()" in preflight
    assert "mode not in (0o400, 0o600)" in preflight
    assert "PYTHONDONTWRITEBYTECODE=1" in script
    assert "source .env" not in script


def test_deploy_shell_contains_no_embedded_python():
    script = _read("deploy.sh")

    for forbidden in (
        "<<'PY'",
        '<<"PY"',
        '"$BOOTSTRAP_PYTHON" -c',
        '"$BOOTSTRAP_PYTHON" -B -c',
        '"$CANDIDATE_PYTHON" -c',
        "python3 -c",
        "python3.12 -c",
    ):
        assert forbidden not in script
    assert "deploy/preflight.py" in script
    assert 'docker-source-digest "$context" "${inputs[@]}"' in script


def test_backup_cli_is_a_thin_entrypoint_over_the_structured_package():
    entrypoint = _read("deploy/backup_database.py")

    assert "from deploy.backup.orchestrator import main" in entrypoint
    assert "def backup_database(" not in entrypoint
    for module in ("policy.py", "apt.py", "physical.py", "paths.py", "orchestrator.py"):
        assert (ROOT / "deploy" / "backup" / module).is_file()


def test_deploy_can_migrate_the_exact_legacy_supervisor_processes():
    script = _read("deploy.sh")

    assert "deploy/legacy_supervisor.py" in script
    assert 'legacy_supervisor_pids web' in script
    assert 'legacy_supervisor_pids celery' in script
    assert "--expected-pids \"$legacy_pids\"" in script
    assert "if [[ \"$pid\" == 'LEGACY' ]]" in script


def test_legacy_supervisor_identity_requires_uid_cwd_entrypoint_and_root_config():
    root = ROOT.resolve()
    uid = 501
    web = legacy_supervisor.ProcessInfo(
        pid=100,
        uid=uid,
        cwd=root,
        argv=("/usr/bin/python3", "/usr/local/bin/supervisord", "-c", "web.conf"),
    )
    celery = legacy_supervisor.ProcessInfo(
        pid=101,
        uid=uid,
        cwd=root,
        argv=("/usr/local/bin/supervisord", "-c", str(root / "celery.conf")),
    )

    assert legacy_supervisor.legacy_service(web, root, expected_uid=uid) == "web"
    assert (
        legacy_supervisor.legacy_service(celery, root, expected_uid=uid)
        == "celery"
    )
    assert (
        legacy_supervisor.legacy_service(
            legacy_supervisor.ProcessInfo(
                pid=102,
                uid=uid,
                cwd=root.parent,
                argv=("supervisord", "-c", str(root / "web.conf")),
            ),
            root,
            expected_uid=uid,
        )
        is None
    )
    assert (
        legacy_supervisor.legacy_service(
            legacy_supervisor.ProcessInfo(
                pid=103,
                uid=uid,
                cwd=root,
                argv=("bash", "supervisord", "-c", "web.conf"),
            ),
            root,
            expected_uid=uid,
        )
        is None
    )
    assert (
        legacy_supervisor.legacy_service(
            legacy_supervisor.ProcessInfo(
                pid=104,
                uid=uid,
                cwd=root,
                argv=("supervisord", "-c", "deploy/supervisor/web.conf"),
            ),
            root,
            expected_uid=uid,
        )
        is None
    )
    assert legacy_supervisor.legacy_service(web, root, expected_uid=uid + 1) is None


def test_legacy_supervisor_revalidates_pid_identity_before_signal(monkeypatch):
    root = ROOT.resolve()
    pid = 200
    monkeypatch.setattr(
        legacy_supervisor,
        "discover",
        lambda *_args, **_kwargs: [pid],
    )
    monkeypatch.setattr(
        legacy_supervisor,
        "_read_process",
        lambda _pid: legacy_supervisor.ProcessInfo(
            pid=pid,
            uid=999,
            cwd=root,
            argv=("supervisord", "-c", "web.conf"),
        ),
    )
    monkeypatch.setattr(
        legacy_supervisor.os,
        "kill",
        lambda *_args: pytest.fail("an identity mismatch must not be signalled"),
    )

    with pytest.raises(RuntimeError, match="changed identity"):
        legacy_supervisor.stop_expected(root, "web", {pid}, timeout=1)


def test_deploy_requires_exact_supervisor_namespecs_and_successful_status_command():
    script = _read("deploy.sh")

    assert "while read -r name state ignored" in script
    assert "if status=\"$(" in script
    assert 'supervisorctl_status=$?' in script
    assert '"$supervisorctl_status" -eq 0' in script
    assert "celery:celery_judge celery:celery_agent celery:celery_agent_judge" in script
    assert 'wait_for_programs "$WEB_CONFIG" 120 web' in script
    assert 'wait_for_programs "$OBSERVABILITY_CONFIG" 15 log_collector' in script
    assert '"${#seen_names[@]}" -eq "${#expected_names[@]}"' in script


def test_deploy_rejects_drift_processes_after_every_stop_and_before_backup():
    script = _read("deploy.sh")
    stop_function = script[
        script.index("stop_supervisor()") : script.index(
            "stop_observability_best_effort()"
        )
    ]
    stopped = script.index("phase='停止现有服务'")
    backup = script.index("phase='创建并验证数据库回滚点'", stopped)
    stopped_section = script[stopped:backup]

    assert 'assert_service_stopped "$label" "$kind"' in stop_function
    assert "assert_service_stopped 'Celery' celery" in stopped_section
    assert "assert_service_stopped 'Web' web" in stopped_section


def test_supervisor_config_keeps_the_expected_process_topology(tmp_path):
    from supervisor.options import ServerOptions

    supervisor_dir = tmp_path / "deploy" / "supervisor"
    supervisor_dir.mkdir(parents=True)
    (tmp_path / "logs" / "supervisor").mkdir(parents=True)
    (tmp_path / "logs" / "services").mkdir(parents=True)

    groups = {}
    for config_name in ("web.conf", "celery.conf", "observability.conf"):
        config_path = supervisor_dir / config_name
        shutil.copyfile(
            ROOT / "deploy" / "supervisor" / config_name,
            config_path,
        )
        options = ServerOptions()
        options.configfile = str(config_path)
        options.process_config(False)
        groups.update(
            {
                group.name: {program.name for program in group.process_configs}
                for group in options.process_group_configs
            }
        )

    assert groups == {
        "web": {"web"},
        "celery": {"celery_judge", "celery_agent", "celery_agent_judge"},
        "log_collector": {"log_collector"},
    }


def test_production_supervisors_use_the_project_local_deploy_venv_only():
    web = _read("deploy/supervisor/web.conf")
    celery = _read("deploy/supervisor/celery.conf")
    observability = _read("deploy/supervisor/observability.conf")

    assert "init_db_schema.py" not in web
    assert "init_db_schema.py" not in celery
    assert '"%(here)s/../../.deploy/current-venv/bin/python3" -m gunicorn' in web
    assert celery.count(
        '"%(here)s/../../.deploy/current-venv/bin/python3" -m celery'
    ) == 3
    assert (
        '"%(here)s/../../.deploy/current-venv/bin/python3" '
        '-B scripts/log_admin.py serve'
    ) in observability
    assert celery.count("startsecs=10") == 3
    assert "/home/" not in web
    assert "/home/" not in celery
    assert "/home/" not in observability
    assert "[unix_http_server]" in web
    assert "[unix_http_server]" in celery
    assert "[unix_http_server]" in observability


def test_obsolete_remote_release_helpers_are_removed():
    obsolete = (
        "deploy/remote.sh",
        "deploy/managed_tree.py",
        "deploy/manifest.py",
        "deploy/process_guard.py",
        "deploy/rsync-excludes.txt",
        "deploy/shell_helpers.sh",
        "deploy/static_files.py",
        "deploy/venv_integrity.py",
    )

    assert not any((ROOT / path).exists() for path in obsolete)
