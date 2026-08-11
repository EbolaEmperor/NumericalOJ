import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import subprocess
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "deploy_preflight", ROOT / "deploy" / "preflight.py"
)
preflight = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(preflight)


def _config(**overrides):
    values = {
        "ENV_FILE_LOADED": True,
        "ENV_FILE_KEYS": frozenset(preflight.REQUIRED_ENV_KEYS),
        "SECRET_KEY": "secret",
        "MYSQL_HOST": "mysql.internal",
        "MYSQL_DB": "numericaloj",
        "MYSQL_USERNAME": "oj",
        "MYSQL_PASSWORD": "password",
        "REDIS_HOST": "redis.internal",
        "MYSQL_PORT": 3306,
        "REDIS_PORT": 6379,
        "REDIS_DB": 0,
        "VIBEHUB_BUILD_BUILDER": "numoj-vibehub",
        "VIBEHUB_REQUIRE_DEDICATED_BUILDER": True,
        "VIBEHUB_BASE_OCI_LAYOUT_ROOT": ".deploy/vibehub-base-oci",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _private_env(tmp_path: Path) -> Path:
    path = tmp_path / ".env"
    path.write_text("SECRET_KEY=secret\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def _buildx_list_output(*builders: dict) -> str:
    return "\n".join(json.dumps(builder) for builder in builders)


def test_validate_config_accepts_a_private_regular_file_and_cli_is_silent(
    monkeypatch, tmp_path, capsys
):
    path = _private_env(tmp_path)
    monkeypatch.setattr(preflight, "_load_project_config", _config)

    assert preflight.main(["validate-config", str(path)]) == 0

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_vibehub_settings_use_validated_defaults_instead_of_required_env_keys():
    assert not any(
        name.startswith("VIBEHUB_") for name in preflight.REQUIRED_ENV_KEYS
    )

    preflight._validate_config_values(_config())


@pytest.mark.parametrize(
    ("overrides", "message"),
    (
        ({"VIBEHUB_BUILD_BUILDER": ""}, "VIBEHUB_BUILD_BUILDER"),
        ({"VIBEHUB_REQUIRE_DEDICATED_BUILDER": False}, "专属 Buildx builder"),
        (
            {"VIBEHUB_BASE_OCI_LAYOUT_ROOT": ".deploy/other-vibehub-oci"},
            "必须指向项目内",
        ),
    ),
)
def test_vibehub_default_overrides_still_fail_closed(overrides, message):
    with pytest.raises(preflight.PreflightError, match=message):
        preflight._validate_config_values(_config(**overrides))


def test_validate_config_rejects_a_symlink(tmp_path):
    target = _private_env(tmp_path)
    link = tmp_path / "linked.env"
    link.symlink_to(target)

    with pytest.raises(preflight.PreflightError, match="不能是符号链接"):
        preflight.validate_production_config(link, config_loader=_config)


@pytest.mark.parametrize("mode", [0o644, 0o660, 0o700])
def test_validate_config_rejects_non_private_permissions(tmp_path, mode):
    path = _private_env(tmp_path)
    path.chmod(mode)

    with pytest.raises(preflight.PreflightError, match="0400 或 0600"):
        preflight.validate_production_config(path, config_loader=_config)


def test_validate_config_rejects_a_different_owner(monkeypatch, tmp_path):
    path = _private_env(tmp_path)
    owner_uid = path.stat().st_uid
    monkeypatch.setattr(preflight.os, "geteuid", lambda: owner_uid + 1)

    with pytest.raises(preflight.PreflightError, match="不属于当前部署用户"):
        preflight.validate_production_config(path, config_loader=_config)


def test_validate_config_detects_a_change_during_config_loading(tmp_path):
    path = _private_env(tmp_path)

    def mutate_then_load():
        path.write_text("SECRET_KEY=changed-and-longer\n", encoding="utf-8")
        return _config()

    with pytest.raises(preflight.PreflightError, match="校验过程中发生变化"):
        preflight.validate_production_config(path, config_loader=mutate_then_load)


def test_validate_config_checks_required_keys_and_decoded_types(tmp_path):
    path = _private_env(tmp_path)
    missing = set(preflight.REQUIRED_ENV_KEYS) - {"REDIS_DB"}

    with pytest.raises(preflight.PreflightError, match="REDIS_DB"):
        preflight.validate_production_config(
            path,
            config_loader=lambda: _config(ENV_FILE_KEYS=missing),
        )

    with pytest.raises(preflight.PreflightError, match="MYSQL_PORT"):
        preflight.validate_production_config(
            path,
            config_loader=lambda: _config(MYSQL_PORT=True),
        )

def test_validate_vibehub_builder_requires_all_running_network_none_nodes():
    calls = []
    builder = {
        "Name": "numoj-vibehub",
        "Driver": "docker-container",
        "Nodes": [
            {"Name": "numoj-vibehub0", "Status": "running"},
            {"Name": "numoj-vibehub1", "Status": "running"},
        ],
    }

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        if command[:3] == ["docker", "buildx", "ls"]:
            return subprocess.CompletedProcess(
                command,
                0,
                _buildx_list_output(
                    {"Name": "default", "Driver": "docker", "Nodes": []},
                    builder,
                ),
                "",
            )
        else:
            name = command[-1]
            payload = {
                "Name": f"/{name}",
                "State": {"Running": True},
                "HostConfig": {"NetworkMode": "none"},
            }
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    assert preflight.validate_vibehub_builder(
        config_loader=_config, command_runner=runner
    ) == "numoj-vibehub"
    assert calls[0][0] == ["docker", "buildx", "ls", "--format", "json"]
    assert [call[0][-1] for call in calls[1:]] == [
        "buildx_buildkit_numoj-vibehub0",
        "buildx_buildkit_numoj-vibehub1",
    ]
    assert all(call[1]["timeout"] == 20 for call in calls)


@pytest.mark.parametrize(
    "builder_patch, container_patch, message",
    [
        ({"Driver": "docker"}, {}, "docker-container"),
        ({"Nodes": [{"Name": "numoj-vibehub0", "Status": "stopped"}]}, {}, "未就绪"),
        ({}, {"HostConfig": {"NetworkMode": "bridge"}}, "network=none"),
        ({}, {"State": {"Running": False}}, "未运行"),
    ],
)
def test_validate_vibehub_builder_fails_closed(
    builder_patch, container_patch, message
):
    builder = {
        "Name": "numoj-vibehub",
        "Driver": "docker-container",
        "Nodes": [{"Name": "numoj-vibehub0", "Status": "running"}],
    }
    builder.update(builder_patch)
    container = {
        "Name": "/buildx_buildkit_numoj-vibehub0",
        "State": {"Running": True},
        "HostConfig": {"NetworkMode": "none"},
    }
    container.update(container_patch)

    def runner(command, **_kwargs):
        if command[:3] == ["docker", "buildx", "ls"]:
            return subprocess.CompletedProcess(
                command, 0, _buildx_list_output(builder), ""
            )
        payload = container
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    with pytest.raises(preflight.PreflightError, match=message):
        preflight.validate_vibehub_builder(
            config_loader=_config, command_runner=runner
        )


def test_validate_vibehub_builder_reports_missing_builder():
    def runner(command, **_kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            _buildx_list_output(
                {"Name": "default", "Driver": "docker", "Nodes": []}
            ),
            "",
        )

    with pytest.raises(preflight.PreflightError, match="未预置.*numoj-vibehub"):
        preflight.validate_vibehub_builder(
            config_loader=_config, command_runner=runner
        )


def test_ensure_vibehub_builder_creates_only_when_missing():
    calls = []
    list_count = 0
    builder = {
        "Name": "numoj-vibehub",
        "Driver": "docker-container",
        "Nodes": [{"Name": "numoj-vibehub0", "Status": "running"}],
    }

    def runner(command, **kwargs):
        nonlocal list_count
        calls.append((command, kwargs))
        if command[:3] == ["docker", "buildx", "ls"]:
            list_count += 1
            payload = (
                {"Name": "default", "Driver": "docker", "Nodes": []}
                if list_count == 1
                else builder
            )
            return subprocess.CompletedProcess(
                command, 0, _buildx_list_output(payload), ""
            )
        if command[:3] == ["docker", "buildx", "create"]:
            return subprocess.CompletedProcess(command, 0, "numoj-vibehub\n", "")
        name = command[-1]
        return subprocess.CompletedProcess(command, 0, json.dumps({
            "Name": f"/{name}",
            "State": {"Running": True},
            "HostConfig": {"NetworkMode": "none"},
        }), "")

    assert preflight.ensure_vibehub_builder(
        config_loader=_config,
        command_runner=runner,
    ) == "numoj-vibehub"
    create = next(
        command for command, _kwargs in calls
        if command[:3] == ["docker", "buildx", "create"]
    )
    assert "--use" not in create
    assert "network=none" in create
    assert f"image={preflight.VIBEHUB_BUILDKIT_IMAGE}" in create


def test_validate_vibehub_builder_preserves_buildx_error():
    def runner(command, **_kwargs):
        return subprocess.CompletedProcess(
            command, 125, "", "unknown flag: --format\n"
        )

    with pytest.raises(
        preflight.PreflightError,
        match="退出码：125.*unknown flag: --format",
    ):
        preflight.validate_vibehub_builder(
            config_loader=_config, command_runner=runner
        )


def _expected_digest(path: Path, relative_name: str) -> str:
    metadata = path.stat()
    name = relative_name.encode("utf-8")
    digest = hashlib.sha256(preflight.SOURCE_DIGEST_DOMAIN)
    digest.update(len(name).to_bytes(8, "big"))
    digest.update(name)
    digest.update(stat.S_IMODE(metadata.st_mode).to_bytes(4, "big"))
    digest.update(metadata.st_size.to_bytes(8, "big"))
    digest.update(path.read_bytes())
    return digest.hexdigest()


def test_docker_source_digest_is_deterministic_and_preserves_output_contract(
    tmp_path, capsys
):
    context = tmp_path / "image"
    context.mkdir()
    dockerfile = context / "Dockerfile"
    dockerfile.write_bytes(b"FROM scratch\n")
    dockerfile.chmod(0o640)
    expected = _expected_digest(dockerfile, "Dockerfile")

    first = preflight.docker_source_digest(context, ["Dockerfile"])
    second = preflight.docker_source_digest(context, ["Dockerfile"])

    assert first == second == expected
    assert re.fullmatch(r"[0-9a-f]{64}", first)
    assert preflight.main(
        ["docker-source-digest", str(context), "Dockerfile"]
    ) == 0
    captured = capsys.readouterr()
    assert captured.out == f"{expected}\n"
    assert captured.err == ""


def test_docker_source_digest_changes_with_content_name_and_mode(tmp_path):
    context = tmp_path / "image"
    context.mkdir()
    source = context / "source"
    source.write_bytes(b"one")
    source.chmod(0o600)
    baseline = preflight.docker_source_digest(context, ["source"])

    source.write_bytes(b"two")
    content_changed = preflight.docker_source_digest(context, ["source"])
    source.rename(context / "renamed")
    name_changed = preflight.docker_source_digest(context, ["renamed"])
    (context / "renamed").chmod(0o640)
    mode_changed = preflight.docker_source_digest(context, ["renamed"])

    assert len({baseline, content_changed, name_changed, mode_changed}) == 4


def test_docker_source_digest_rejects_symlinks(tmp_path):
    context = tmp_path / "image"
    context.mkdir()
    target = context / "target"
    target.write_text("content", encoding="utf-8")
    (context / "source").symlink_to(target)

    with pytest.raises(preflight.PreflightError, match="必须是普通文件"):
        preflight.docker_source_digest(context, ["source"])


def test_docker_source_digest_rejects_paths_outside_the_context(tmp_path):
    context = tmp_path / "image"
    context.mkdir()
    (tmp_path / "secret").write_text("secret", encoding="utf-8")

    with pytest.raises(preflight.PreflightError, match="路径无效"):
        preflight.docker_source_digest(context, ["../secret"])
