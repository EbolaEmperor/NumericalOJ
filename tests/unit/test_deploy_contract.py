from pathlib import Path
import subprocess

import pytest

from deploy import legacy_supervisor


ROOT = Path(__file__).resolve().parents[2]


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


def test_deploy_prepares_candidates_before_stopping_and_then_restarts_everything():
    script = _read("deploy.sh")
    phases = [
        "phase='准备 Python 运行环境'",
        "phase='构建判题镜像'",
        "phase='备份数据库'",
        "phase='确认现有服务可管理'",
        "phase='停止现有服务'",
        "phase='切换运行环境并更新数据库结构'",
        "phase='切换判题镜像'",
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
    assert "deploy/backup_database.py --output" in script
    assert "scripts/init_db_schema.py" in script
    assert "scripts/recover_pending_tasks.py --confirm-celery-stopped" in script
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


def test_deploy_detects_and_imports_stable_docker_build_cache():
    script = _read("deploy.sh")

    assert 'DOCKER_BUILDER="${NUMOJ_DOCKER_BUILDER:-default}"' in script
    assert "JUDGER_STABLE='numericaloj-judger:latest'" in script
    assert "AGENT_JUDGE_STABLE='numericaloj-agent-judge:latest'" in script
    assert 'docker buildx inspect "$DOCKER_BUILDER"' in script
    assert "docker info --format '{{.DockerRootDir}}'" in script
    assert "docker buildx du" in script
    assert '--builder "$DOCKER_BUILDER"' in script
    assert "docker image inspect --format '{{.Id}}' \"$stable\"" in script
    assert 'cache_args+=(--cache-from "$stable")' in script
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
    assert "os.replace(sys.argv[1], sys.argv[2])" in script
    assert "LOCK_FILE='/tmp/noj_deploy.lock'" in script
    assert 'exec 9>>"$LOCK_FILE"' in script
    assert '"$STATE_DIR/deploy.lock"' not in script
    assert "flock -n 9" in script
    assert script.count('"$CANDIDATE_SUPERVISORD" -c ') == 2
    assert script.count('"$CANDIDATE_SUPERVISORD" -c "$CELERY_CONFIG" 9>&-') == 1
    assert script.count('"$CANDIDATE_SUPERVISORD" -c "$WEB_CONFIG" 9>&-') == 1
    assert 'BACKUP_DIR="$STATE_DIR/backups"' in script


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

    config_check = script.index("phase='校验生产本地配置'")
    dependency_install = script.index("phase='准备 Python 运行环境'")
    image_build = script.index("phase='构建判题镜像'")
    database_backup = script.index("phase='备份数据库'")
    assert config_check < dependency_install < image_build < database_backup
    assert 'ENV_FILE="$ROOT_DIR/.env"' in script
    assert "config.ENV_FILE_LOADED" in script
    assert "config.ENV_FILE_KEYS" in script
    assert "metadata.st_uid != os.geteuid()" in script
    assert "mode not in (0o400, 0o600)" in script
    assert "PYTHONDONTWRITEBYTECODE=1" in script
    assert "source .env" not in script


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


def test_deploy_checks_all_programs_from_supervisor_status_without_namespec_copy():
    script = _read("deploy.sh")

    assert "while read -r name state ignored" in script
    assert "celery:celery_judge" not in script
    assert "celery:celery_agent" not in script


def test_supervisor_config_keeps_the_expected_process_topology():
    from supervisor.options import ServerOptions

    groups = {}
    for config_name in ("web.conf", "celery.conf"):
        options = ServerOptions()
        options.configfile = str(ROOT / "deploy" / "supervisor" / config_name)
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
    }


def test_production_supervisors_use_the_project_local_deploy_venv_only():
    web = _read("deploy/supervisor/web.conf")
    celery = _read("deploy/supervisor/celery.conf")

    assert "init_db_schema.py" not in web
    assert "init_db_schema.py" not in celery
    assert '"%(here)s/../../.deploy/current-venv/bin/python3" -m gunicorn' in web
    assert celery.count(
        '"%(here)s/../../.deploy/current-venv/bin/python3" -m celery'
    ) == 3
    assert celery.count("startsecs=10") == 3
    assert "/home/" not in web
    assert "/home/" not in celery
    assert "[unix_http_server]" in web
    assert "[unix_http_server]" in celery


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
