"""首次部署配置与宿主供应的安全边界。"""

import json
from pathlib import Path
import subprocess

import pytest

from deploy import bootstrap


def test_existing_private_configuration_is_never_rewritten(tmp_path):
    path = tmp_path / ".env"
    original = 'SECRET_KEY="existing-site-secret"\nMYSQL_PASSWORD="keep-me"\n'
    path.write_text(original)
    path.chmod(0o400)
    assert bootstrap.ensure_configuration(tmp_path, interactive=False) is False
    assert path.read_text() == original
    assert path.stat().st_mode & 0o777 == 0o400


@pytest.mark.parametrize("kind", ["public", "symlink"])
def test_existing_configuration_must_pass_metadata_checks(tmp_path, kind):
    path = tmp_path / ".env"
    if kind == "public":
        path.write_text("SECRET_KEY=bad\n")
        path.chmod(0o644)
    else:
        target = tmp_path / "target"
        target.write_text("SECRET_KEY=bad\n")
        path.symlink_to(target)
    with pytest.raises(bootstrap.BootstrapError, match="0400/0600"):
        bootstrap.ensure_configuration(tmp_path, interactive=False)


def test_new_configuration_requires_an_explicit_interactive_new_site_choice(tmp_path):
    with pytest.raises(bootstrap.BootstrapError, match="交互终端"):
        bootstrap.ensure_configuration(tmp_path, interactive=False)
    with pytest.raises(bootstrap.BootstrapError, match="不会猜测或替换凭据"):
        bootstrap.ensure_configuration(tmp_path, interactive=True, input_fn=lambda: "no")
    assert not (tmp_path / ".env").exists()


def test_test_cpu_initialization_uses_disposable_defaults_and_private_secrets(tmp_path, capsys):
    answers = iter(("yes", ""))
    assert bootstrap.ensure_configuration(tmp_path, profile="test-cpu", interactive=True, input_fn=lambda: next(answers))
    path = tmp_path / ".env"
    values = dict(line.split("=", 1) for line in path.read_text().splitlines() if line and not line.startswith("#"))
    assert json.loads(values["MYSQL_DB"]) == "numoj_dev_test"
    assert json.loads(values["REDIS_DB"]) == 15
    assert len(json.loads(values["SECRET_KEY"])) >= 48
    password = json.loads(values["MYSQL_PASSWORD"])
    assert len(password) >= 32
    assert path.stat().st_mode & 0o777 == 0o600
    assert password not in capsys.readouterr().err
    assert (tmp_path / ".deploy/new-local-site.json").stat().st_mode & 0o777 == 0o600


def test_profile_is_persistent_and_existing_sites_keep_production_default(tmp_path):
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    assert bootstrap.resolve_profile(fresh, gpu_available=False) == "test-cpu"
    assert bootstrap.resolve_profile(fresh, gpu_available=True) == "test-cpu"
    assert bootstrap.resolve_profile(fresh, "production") == "production"
    old = tmp_path / "old"
    old.mkdir()
    (old / ".env").write_text("existing")
    assert bootstrap.resolve_profile(old, gpu_available=False) == "production"
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap.resolve_profile(fresh, "unknown")


@pytest.mark.parametrize("unsafe", ["Remv mysql-server [8.0]", "Inst mysql-server [8.0] (8.4 Ubuntu)", "Inst libexisting [1] (2 Ubuntu)", "Conf mysql-server (8.0 Ubuntu)", "Inst mysql-server (8.4 Ubuntu)"])
def test_first_package_supply_rejects_replacement_of_existing_packages(monkeypatch, unsafe):
    monkeypatch.setattr(bootstrap.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(bootstrap, "_apt_supported", lambda: True)
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        output = "Candidate: 1.2.3\n" if command[:2] == ["apt-cache", "policy"] else unsafe if "--simulate" in command else ""
        return subprocess.CompletedProcess(command, 0, output, "")
    with pytest.raises(bootstrap.BootstrapError, match="删除或升级"):
        bootstrap._install_missing([("new-tool",)], run=run)
    assert not any("--yes" in command for command in calls)


def test_package_supply_uses_exact_candidate_after_a_clean_simulation(monkeypatch):
    monkeypatch.setattr(bootstrap.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(bootstrap, "_apt_supported", lambda: True)
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        output = "Candidate: 4.5.6\n" if command[:2] == ["apt-cache", "policy"] else "Inst fresh (4.5.6 Ubuntu)"
        return subprocess.CompletedProcess(command, 0, output, "")
    bootstrap._install_missing([("fresh",)], run=run)
    install = next(command for command in calls if "--yes" in command)
    assert "fresh=4.5.6" in install and "--no-remove" in install


def test_apt_proxy_is_private_removed_and_never_puts_credentials_in_arguments(monkeypatch):
    proxy = "http://user:private-proxy-password@127.0.0.1:18080"
    monkeypatch.setattr(bootstrap, "_apt_supported", lambda: True)
    monkeypatch.setattr(bootstrap, "_download_proxy_values", lambda: {"HTTP_PROXY": proxy, "HTTPS_PROXY": proxy})
    paths = []
    def run(command, **kwargs):
        assert all("private-proxy-password" not in argument for argument in command)
        if "apt-get" in command:
            path = Path(command[command.index("-c") + 1])
            paths.append(path)
            assert path.stat().st_mode & 0o777 == 0o600
            assert f'Acquire::https::Proxy "{proxy}";' in path.read_text()
        output = "Candidate: 4.5.6\n" if command[:2] == ["apt-cache", "policy"] else "Inst fresh (4.5.6 Ubuntu)"
        return subprocess.CompletedProcess(command, 0, output, "")
    bootstrap._install_missing([("fresh",)], run=run)
    assert len(paths) == 3 and not any(path.exists() for path in paths)


def test_host_downloads_reuse_saved_proxy_without_shell_environment(monkeypatch, tmp_path):
    state = tmp_path / ".deploy/download-proxy.json"
    state.parent.mkdir()
    state.write_text(json.dumps({"root": str(tmp_path), "environment": {"HTTP_PROXY": "http://127.0.0.1:18080"}}))
    state.chmod(0o600)
    monkeypatch.setattr(bootstrap, "ROOT", tmp_path)
    assert bootstrap._download_proxy_values()["HTTP_PROXY"] == "http://127.0.0.1:18080"


def test_download_proxy_does_not_reach_application_commands():
    script = (Path(__file__).resolve().parents[3] / "deploy.sh").read_text()
    start = script.index("clear_download_proxy_environment() {")
    function = script[start:script.index("\n}\n", start) + 3]
    source = function + r'''
for name in HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy; do
  export "$name=temporary-download-proxy"
done
export NUMOJ_KEEP_RUNTIME_SETTING=retained
clear_download_proxy_environment
env
'''
    result = subprocess.run(["bash", "-c", source], capture_output=True, text=True)
    assert result.returncode == 0
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    assert not set(values) & {"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"}
    assert values["NUMOJ_KEEP_RUNTIME_SETTING"] == "retained"
    boundary = script.index("\nclear_download_proxy_environment\n")
    assert script.index('"$CANDIDATE_PYTHON" -m pip install') < boundary
    assert script.index("phase='构建判题镜像'") < boundary
    assert script.index("phase='准备数据库备份计划'") < boundary
    for command in (
        '"$CANDIDATE_PYTHON" scripts/init_db_schema.py',
        '"$CANDIDATE_PYTHON" -B deploy/seed_vibehub_examples.py',
        '"$CANDIDATE_PYTHON" scripts/recover_pending_tasks.py',
        '"$CANDIDATE_SUPERVISORD" -c "$OBSERVABILITY_CONFIG"',
        '"$CANDIDATE_SUPERVISORD" -c "$CELERY_CONFIG"',
        '"$CANDIDATE_SUPERVISORD" -c "$WEB_CONFIG"',
    ):
        assert boundary < script.index(command)


@pytest.mark.parametrize("with_proxy", [False, True])
def test_frontend_download_container_receives_only_proxy_keys(with_proxy):
    script = (Path(__file__).resolve().parents[3] / "deploy.sh").read_text()
    start = script.index("configure_download_container_proxy() {")
    function = script[start:script.index("\n}\n", start) + 3]
    source = function + r'''
unset HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy
if [[ "$1" == yes ]]; then
  export HTTP_PROXY=http://user:private-download-password@127.0.0.1:18080
  export HTTPS_PROXY="$HTTP_PROXY" NO_PROXY=localhost,127.0.0.1
  export http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" no_proxy="$NO_PROXY"
fi
configure_download_container_proxy
printf '%s\n' "${DEPLOY_DOWNLOAD_CONTAINER_ARGUMENTS[@]}"
'''
    result = subprocess.run(["bash", "-c", source, "download-container-test", "yes" if with_proxy else "no"], capture_output=True, text=True)
    assert result.returncode == 0
    if with_proxy:
        assert result.stdout.splitlines() == ["--network", "host", "--env", "HTTP_PROXY", "--env", "HTTPS_PROXY", "--env", "NO_PROXY", "--env", "http_proxy", "--env", "https_proxy", "--env", "no_proxy"]
    else:
        assert not result.stdout.strip()
    assert "private-download-password" not in result.stdout
    frontend = script[script.index("phase='构建 React 前端'"):script.index("phase='生成预压缩静态资源'")]
    assert '"${DEPLOY_DOWNLOAD_CONTAINER_ARGUMENTS[@]}"' in frontend
    assert script.count('"${DEPLOY_DOWNLOAD_CONTAINER_ARGUMENTS[@]}"') == 1


def test_host_preparation_precedes_docker_preflight_and_keeps_schema_after_backup():
    script = (Path(__file__).resolve().parents[3] / "deploy.sh").read_text()
    assert script.index("deploy/bootstrap.py") < script.index('for command_name in docker flock git pgrep')
    assert script.index("deploy/bootstrap_services.py") < script.index("phase='准备数据库备份计划'")
    assert script.index("phase='创建并验证数据库回滚点'") < script.index("scripts/init_db_schema.py")
    assert script.index("scripts/init_db_schema.py") < script.index("bootstrap_site.py initialize-admin")
    assert "exec sg docker" in script
    assert 'docker tag "$HARBOR_BASE_CANDIDATE" "$HARBOR_BASE_STABLE"' in script


@pytest.mark.parametrize("simulation,success", [
    ("Inst python3 (3.12 Ubuntu)\nConf python3 (3.12 Ubuntu)", True),
    ("Remv libexisting [1]", False),
    ("Inst libexisting [1] (2 Ubuntu)", False),
    ("Conf libexisting (1 Ubuntu)", False),
    ("Inst mysql-server-8.0 (8.0 Ubuntu)", False),
    ("Conf mariadb-server (10 Ubuntu)", False),
])
def test_minimal_shell_install_has_the_same_pre_backup_package_guards(tmp_path, simulation, success):
    script = (Path(__file__).resolve().parents[3] / "deploy.sh").read_text()
    start = script.index("bootstrap_install_missing() {")
    function = script[start:script.index("\n}\n", start) + 3]
    calls = tmp_path / "installed"
    source = function + r'''
apt-cache() { printf 'Candidate: 3.12\n'; }
bootstrap_apt() {
  if [[ "$1" == --simulate ]]; then
    printf '%s\n' "$SIMULATION"
  else
    printf '%s\n' "$*" > "$CALLS_FILE"
  fi
}
SIMULATION="$1"
CALLS_FILE="$2"
bootstrap_install_missing python3
'''
    result = subprocess.run(["bash", "-c", source, "minimal-bootstrap-test", simulation, str(calls)], capture_output=True, text=True)
    assert (result.returncode == 0) is success, result.stderr
    if success:
        assert calls.read_text().strip() == "--yes --no-install-recommends --no-remove install python3=3.12"
    else:
        assert not calls.exists()
