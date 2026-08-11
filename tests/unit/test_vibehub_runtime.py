from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import stat
import threading
import tempfile
import shutil
import time

import pytest

from oj_modules.vibehub import runtime


_BASE_ID = "sha256:" + "1" * 64
_APP_ID = "sha256:" + "2" * 64


@pytest.fixture
def short_tmp():
    path = Path(tempfile.mkdtemp(prefix="vh-test-", dir="/tmp"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _write_package(root: Path, dockerfile: str | None = None) -> Path:
    root.mkdir()
    (root / "vibehub.json").write_text(
        json.dumps({
            "schema_version": 1,
            "transport": "unix",
            "socket_path": "/run/vibehub/app.sock",
            "health_path": "/healthz",
            "title": "测试作品",
            "cover_image": "static/cover.jpg",
        }),
        encoding="utf-8",
    )
    (root / "Dockerfile").write_text(
        dockerfile
        or (
            "FROM numericaloj-vibehub-runtime:1\n"
            "COPY . /app\n"
            '["python", "/app/app.py"]\n'.replace("[", "CMD [", 1)
        ),
        encoding="utf-8",
    )
    (root / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (root / "static").mkdir()
    shutil.copyfile(
        Path(__file__).resolve().parents[2]
        / "vibehub_examples/circle-cat/static/cover.jpg",
        root / "static/cover.jpg",
    )
    return root


def _write_base_oci_layout(
    root: Path,
    *,
    reference: str = runtime.DEFAULT_BASE_IMAGE,
    image_id: str = _BASE_ID,
) -> tuple[Path, str]:
    release = root / "releases" / image_id.removeprefix("sha256:")
    blobs = release / "blobs" / "sha256"
    blobs.mkdir(parents=True)
    config_bytes = b"{}"
    layer_bytes = b"layer"
    layer_digest = "sha256:" + hashlib.sha256(layer_bytes).hexdigest()
    manifest_bytes = json.dumps({
        "schemaVersion": 2,
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": image_id,
            "size": len(config_bytes),
        },
        "layers": [{
            "mediaType": "application/vnd.oci.image.layer.v1.tar",
            "digest": layer_digest,
            "size": len(layer_bytes),
        }],
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest_digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    (blobs / manifest_digest.removeprefix("sha256:")).write_bytes(manifest_bytes)
    (blobs / image_id.removeprefix("sha256:")).write_bytes(config_bytes)
    (blobs / layer_digest.removeprefix("sha256:")).write_bytes(layer_bytes)
    (release / "oci-layout").write_text(
        json.dumps({"imageLayoutVersion": "1.0.0"}),
        encoding="utf-8",
    )
    (release / "index.json").write_text(json.dumps({
        "schemaVersion": 2,
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": manifest_digest,
            "size": len(manifest_bytes),
        }],
    }), encoding="utf-8")
    (release / "metadata.json").write_text(json.dumps({
        "schema_version": 1,
        "engine_image_ref": reference,
        "engine_image_id": image_id,
        "manifest_digest": manifest_digest,
        "blobs": [
            {"digest": manifest_digest, "size": len(manifest_bytes)},
            {"digest": image_id, "size": len(config_bytes)},
            {"digest": layer_digest, "size": len(layer_bytes)},
        ],
    }), encoding="utf-8")
    (root / "current").symlink_to(Path("releases") / release.name)
    return release, manifest_digest


def _buildx_list_output(
    *,
    builder: str = "numoj-vibehub",
    driver: str = "docker-container",
    status: str = "running",
) -> str:
    return "\n".join(json.dumps(item) for item in (
        {"Name": "default", "Driver": "docker", "Nodes": []},
        {
            "Name": builder,
            "Driver": driver,
            "Nodes": [{"Name": f"{builder}0", "Status": status}],
        },
    ))


def _buildx_node_inspect_payload(
    *,
    builder: str = "numoj-vibehub",
    network_mode: str = "none",
) -> str:
    return json.dumps({
        "Name": f"/buildx_buildkit_{builder}0",
        "State": {"Running": True},
        "HostConfig": {"NetworkMode": network_mode},
    })


class _FakeDocker:
    def __init__(self):
        self.running: set[str] = set()
        self.run_commands: list[list[str]] = []
        self.stopped: list[str] = []
        self.orphans: dict[str, dict[str, str]] = {}
        self.managed_image_prunes = 0
        self.build_cache_prunes = 0
        self.removed_image_references: list[tuple[str, str]] = []
        self.data_volumes: dict[str, tuple[str, str]] = {}
        self.data_write_checks: list[str] = []

    def inspect_image(self, reference):
        return runtime.ImageInfo(
            str(reference),
            _APP_ID,
            1024,
            {runtime.MANAGED_IMAGE_LABEL: "1", runtime.SOURCE_DIGEST_LABEL: "source"},
        )

    def build(self, *_args, **_kwargs):
        raise AssertionError("lifecycle test must not build")

    def prune_managed_dangling_images(self):
        self.managed_image_prunes += 1

    def prune_dedicated_build_cache(self):
        self.build_cache_prunes += 1

    def remove_managed_image_reference(self, reference, expected_image_id):
        self.removed_image_references.append((reference, expected_image_id))
        return True

    def run_container(self, args):
        args = list(args)
        self.run_commands.append(args)
        name = args[args.index("--name") + 1]
        self.running.add(name)

    def ensure_data_volume(self, name, *, scope, storage_key):
        identity = (scope, storage_key)
        previous = self.data_volumes.setdefault(name, identity)
        if previous != identity:
            raise runtime.VibeHubRuntimeError("volume identity mismatch")

    def verify_data_writable(self, container_name):
        self.data_write_checks.append(container_name)

    def remove_container(self, name):
        if name in self.running or name in self.orphans:
            self.stopped.append(name)
        self.running.discard(name)
        self.orphans.pop(name, None)

    def container_running(self, name):
        return name in self.running

    def list_scoped_containers(self, _scope):
        return tuple(self.orphans)

    def container_labels(self, name):
        return self.orphans.get(name)

    def relay_http(self, *_args, **_kwargs):
        raise AssertionError("lifecycle test must not proxy")


def _hold_capacity_locks(runtime_root, lock_names, ready, release):
    import fcntl

    descriptors = []
    try:
        for name in lock_names:
            fd = os.open(Path(runtime_root) / name, os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            descriptors.append(fd)
        ready.set()
        release.wait(5)
    finally:
        for fd in descriptors:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def _manager(monkeypatch, tmp_path, *, docker=None, clock=lambda: 100.0, **kwargs):
    kwargs.setdefault("proxy_transport", "docker-exec")
    manager = runtime.VibeHubRuntimeManager(
        tmp_path / "runtime",
        docker_client=docker or _FakeDocker(),
        clock=clock,
        **kwargs,
    )
    monkeypatch.setattr(manager, "_wait_ready", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(manager, "_probe_runtime_health", lambda *_args, **_kwargs: None)
    acquire = manager.acquire

    def acquire_test_project(*args, **acquire_kwargs):
        acquire_kwargs.setdefault("storage_key", "project-1-public")
        return acquire(*args, **acquire_kwargs)

    monkeypatch.setattr(manager, "acquire", acquire_test_project)
    return manager


def test_build_is_offline_bounded_and_inspects_final_image(tmp_path):
    package = _write_package(tmp_path / "package")
    commands: list[list[str]] = []
    command_timeouts: list[float] = []
    source_digest = ""

    def runner(command, *, timeout, env=None):
        nonlocal source_digest
        command = list(command)
        commands.append(command)
        command_timeouts.append(timeout)
        if command[:3] == ["docker", "image", "inspect"]:
            reference = command[-1]
            if reference == runtime.DEFAULT_BASE_IMAGE:
                payload = {"Id": _BASE_ID, "Size": 123, "Config": {"Labels": {}}}
            else:
                payload = {
                    "Id": _APP_ID,
                    "Size": 10 * 1024 * 1024,
                    "Config": {"Labels": {
                        runtime.MANAGED_IMAGE_LABEL: "1",
                        runtime.SOURCE_DIGEST_LABEL: source_digest,
                    }},
                }
            return runtime._CommandResult(0, json.dumps(payload), "")
        assert command[:2] == ["docker", "build"]
        labels = [
            command[index + 1]
            for index, item in enumerate(command)
            if item == "--label"
        ]
        source_digest = next(
            label.split("=", 1)[1]
            for label in labels
            if label.startswith(runtime.SOURCE_DIGEST_LABEL + "=")
        )
        assert env["DOCKER_BUILDKIT"] == "1"
        return runtime._CommandResult(0, _APP_ID, "")

    result = runtime.build_image(
        package,
        "numoj-vibehub:test",
        docker_client=runtime.DockerCLI(command_runner=runner),
    )

    assert result.image_id == _APP_ID
    build = next(command for command in commands if command[:2] == ["docker", "build"])
    assert command_timeouts[commands.index(build)] == 480
    for flag, value in (
        ("--network", "none"),
        ("--memory", "4g"),
        ("--memory-swap", "4g"),
        ("--cpu-period", "100000"),
        ("--cpu-quota", "200000"),
        ("--pull=false", None),
        ("--force-rm", None),
        ("--quiet", None),
    ):
        assert flag in build
        if value is not None:
            assert build[build.index(flag) + 1] == value
    # FROM 必须在 build 前已作为本地镜像成功 inspect。
    assert commands[0][-1] == runtime.DEFAULT_BASE_IMAGE


def test_buildx_missing_uses_one_exact_legacy_fallback_with_same_command(tmp_path):
    package = _write_package(tmp_path / "package")
    calls: list[tuple[list[str], str]] = []

    def runner(command, *, timeout, env=None):
        calls.append((list(command), env["DOCKER_BUILDKIT"]))
        if len(calls) == 1:
            return runtime._CommandResult(
                1,
                "",
                "ERROR: BuildKit is enabled but the buildx component is missing or broken.",
            )
        return runtime._CommandResult(0, _APP_ID, "legacy builder deprecation warning")

    runtime.DockerCLI(command_runner=runner).build(
        package,
        "numoj-vibehub:test",
        source_digest="a" * 64,
        limits=runtime.limits_for(False),
        timeout=30,
    )

    assert [mode for _command, mode in calls] == ["1", "0"]
    assert calls[0][0] == calls[1][0]
    assert "--network" in calls[1][0]
    assert calls[1][0][calls[1][0].index("--network") + 1] == "none"


def test_dedicated_builder_uses_buildx_load_and_never_legacy_fallback(tmp_path):
    package = _write_package(tmp_path / "package")
    oci_root = tmp_path / "base-oci"
    release, manifest_digest = _write_base_oci_layout(oci_root)
    calls: list[tuple[list[str], str | None]] = []

    def runner(command, *, timeout, env=None):
        command = list(command)
        calls.append((command, None if env is None else env.get("DOCKER_BUILDKIT")))
        if command[:3] == ["docker", "buildx", "ls"]:
            return runtime._CommandResult(0, _buildx_list_output(), "")
        if command[:3] == ["docker", "container", "inspect"]:
            return runtime._CommandResult(0, _buildx_node_inspect_payload(), "")
        assert command[:3] == ["docker", "buildx", "build"]
        return runtime._CommandResult(0, _APP_ID, "")

    runtime.DockerCLI(
        command_runner=runner,
        build_builder="numoj-vibehub",
        base_oci_layout_root=oci_root,
    ).build(
        package,
        "numoj-vibehub:test",
        source_digest="a" * 64,
        resolved_bases=((runtime.DEFAULT_BASE_IMAGE, _BASE_ID),),
        limits=runtime.limits_for(False),
        timeout=30,
    )

    assert len(calls) == 3
    build = calls[2][0]
    assert build[:3] == ["docker", "buildx", "build"]
    assert build[build.index("--builder") + 1] == "numoj-vibehub"
    assert "--load" in build
    expected_context = (
        f"{runtime.DEFAULT_BASE_IMAGE}=oci-layout://{release.as_posix()}"
        f"@{manifest_digest}"
    )
    assert build[build.index("--build-context") + 1] == expected_context
    assert "--pull=false" in build
    assert "--force-rm" not in build
    assert "--memory" not in build
    resources = [
        build[index + 1]
        for index, value in enumerate(build)
        if value == "--resource"
    ]
    assert resources == [
        "memory=4g",
        "memory-swap=4g",
        "cpu-period=100000",
        "cpu-quota=200000",
    ]
    assert calls[2][1] == "1"


def test_dedicated_builder_fails_closed_when_oci_current_mismatches_base(tmp_path):
    package = _write_package(tmp_path / "package")
    oci_root = tmp_path / "base-oci"
    release, _manifest_digest = _write_base_oci_layout(oci_root)
    metadata_path = release / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["engine_image_ref"] = "other/base:1"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    commands = []

    def runner(command, *, timeout, env=None):
        commands.append(list(command))
        if list(command)[:3] == ["docker", "container", "inspect"]:
            return runtime._CommandResult(0, _buildx_node_inspect_payload(), "")
        return runtime._CommandResult(
            0,
            _buildx_list_output(),
            "",
        )

    with pytest.raises(runtime.VibeHubImageError, match="基础镜像不一致"):
        runtime.DockerCLI(
            command_runner=runner,
            build_builder="numoj-vibehub",
            base_oci_layout_root=oci_root,
        ).build(
            package,
            "numoj-vibehub:test",
            source_digest="a" * 64,
            resolved_bases=((runtime.DEFAULT_BASE_IMAGE, _BASE_ID),),
            limits=runtime.limits_for(False),
            timeout=30,
        )

    assert commands == [
        ["docker", "buildx", "ls", "--format", "json"],
        [
            "docker", "container", "inspect", "--format", "{{json .}}",
            "buildx_buildkit_numoj-vibehub0",
        ],
    ]


def test_cache_cleanup_is_scoped_to_managed_images_and_dedicated_builder():
    commands: list[list[str]] = []

    def runner(command, *, timeout, env=None):
        command = list(command)
        commands.append(command)
        if command[:3] == ["docker", "buildx", "ls"]:
            return runtime._CommandResult(0, _buildx_list_output(), "")
        if command[:3] == ["docker", "container", "inspect"]:
            return runtime._CommandResult(0, _buildx_node_inspect_payload(), "")
        return runtime._CommandResult(0, "", "")

    docker = runtime.DockerCLI(
        command_runner=runner,
        build_builder="numoj-vibehub",
        build_cache_max_bytes=2 * runtime.GIB,
    )
    docker.prune_managed_dangling_images()
    docker.prune_dedicated_build_cache()

    image_prune = commands[0]
    assert image_prune == [
        "docker", "image", "prune", "--force", "--filter",
        f"label={runtime.MANAGED_IMAGE_LABEL}=1",
    ]
    assert "-a" not in image_prune
    cache_prune = commands[-1]
    assert cache_prune == [
        "docker", "buildx", "prune",
        "--builder", "numoj-vibehub",
        "--force", "--max-used-space", str(2 * runtime.GIB),
    ]
    assert not any(command[:3] == ["docker", "builder", "prune"] for command in commands)


def test_local_legacy_mode_never_runs_global_builder_prune():
    commands = []

    def runner(command, *, timeout, env=None):
        commands.append(list(command))
        return runtime._CommandResult(0, "", "")

    docker = runtime.DockerCLI(command_runner=runner)
    docker.prune_dedicated_build_cache()

    assert commands == []


def test_dedicated_builder_rejects_shared_or_wrong_driver():
    def runner(command, *, timeout, env=None):
        return runtime._CommandResult(
            0,
            _buildx_list_output(driver="docker"),
            "",
        )

    with pytest.raises(runtime.VibeHubImageError, match="docker-container"):
        runtime.DockerCLI(
            command_runner=runner,
            build_builder="numoj-vibehub",
        ).verify_dedicated_builder()


def test_dedicated_builder_reports_missing_builder():
    output = json.dumps({"Name": "default", "Driver": "docker", "Nodes": []})

    def runner(command, *, timeout, env=None):
        return runtime._CommandResult(0, output, "")

    with pytest.raises(runtime.VibeHubImageError, match="未预置.*numoj-vibehub"):
        runtime.DockerCLI(
            command_runner=runner,
            build_builder="numoj-vibehub",
        ).verify_dedicated_builder()


def test_dedicated_builder_rejects_networked_buildkit_node():
    def runner(command, *, timeout, env=None):
        command = list(command)
        if command[:3] == ["docker", "buildx", "ls"]:
            return runtime._CommandResult(0, _buildx_list_output(), "")
        return runtime._CommandResult(
            0,
            _buildx_node_inspect_payload(network_mode="bridge"),
            "",
        )

    with pytest.raises(runtime.VibeHubImageError, match="NetworkMode=none"):
        runtime.DockerCLI(
            command_runner=runner,
            build_builder="numoj-vibehub",
        ).verify_dedicated_builder()


def test_dedicated_builder_verifies_every_running_node_is_networkless():
    inspected_containers = []
    output = json.dumps({
        "Name": "numoj-vibehub",
        "Driver": "docker-container",
        "Nodes": [
            {"Name": "numoj-vibehub0", "Status": "running"},
            {"Name": "numoj-vibehub1", "Status": "running"},
        ],
    })

    def runner(command, *, timeout, env=None):
        command = list(command)
        if command[:3] == ["docker", "buildx", "ls"]:
            return runtime._CommandResult(0, output, "")
        name = command[-1]
        inspected_containers.append(name)
        return runtime._CommandResult(0, json.dumps({
            "Name": "/" + name,
            "State": {"Running": True},
            "HostConfig": {"NetworkMode": "none"},
        }), "")

    runtime.DockerCLI(
        command_runner=runner,
        build_builder="numoj-vibehub",
    ).verify_dedicated_builder()

    assert inspected_containers == [
        "buildx_buildkit_numoj-vibehub0",
        "buildx_buildkit_numoj-vibehub1",
    ]


def test_idle_image_tag_cleanup_skips_a_retagged_or_unmanaged_image():
    commands = []
    replacement_id = "sha256:" + "9" * 64

    def runner(command, *, timeout, env=None):
        command = list(command)
        commands.append(command)
        return runtime._CommandResult(0, json.dumps({
            "Id": replacement_id,
            "Config": {"Labels": {runtime.MANAGED_IMAGE_LABEL: "1"}},
        }), "")

    removed = runtime.DockerCLI(
        command_runner=runner,
    ).remove_managed_image_reference("numoj-vibehub:test", _APP_ID)

    assert removed is False
    assert len(commands) == 1
    assert commands[0][:3] == ["docker", "image", "inspect"]


def test_idle_image_tag_cleanup_removes_only_the_exact_verified_reference():
    commands = []

    def runner(command, *, timeout, env=None):
        command = list(command)
        commands.append(command)
        if command[:3] == ["docker", "image", "inspect"]:
            return runtime._CommandResult(0, json.dumps({
                "Id": _APP_ID,
                "Config": {"Labels": {runtime.MANAGED_IMAGE_LABEL: "1"}},
            }), "")
        return runtime._CommandResult(0, "Untagged", "")

    removed = runtime.DockerCLI(
        command_runner=runner,
    ).remove_managed_image_reference("numoj-vibehub:test", _APP_ID)

    assert removed is True
    assert commands[-1] == [
        "docker", "image", "rm", "numoj-vibehub:test",
    ]


def test_other_build_failure_never_uses_legacy_fallback(tmp_path):
    package = _write_package(tmp_path / "package")
    calls = []

    def runner(command, *, timeout, env=None):
        calls.append(env["DOCKER_BUILDKIT"])
        return runtime._CommandResult(1, "", "Dockerfile RUN failed")

    with pytest.raises(runtime.VibeHubImageError, match="离线构建失败"):
        runtime.DockerCLI(command_runner=runner).build(
            package,
            "numoj-vibehub:test",
            source_digest="a" * 64,
            limits=runtime.limits_for(False),
            timeout=30,
        )
    assert calls == ["1"]


@pytest.mark.parametrize("dockerfile", [
    "FROM docker.io/library/python:3.12\nCOPY . /app\n",
    "# syntax=docker/dockerfile:1\nFROM numericaloj-vibehub-runtime:1\n",
    "FROM numericaloj-vibehub-runtime:1\nADD https://example.test/a /app/a\n",
    "FROM numericaloj-vibehub-runtime:1\nRUN --network=host true\n",
    "FROM numericaloj-vibehub-runtime:1\nCOPY --from=nginx /x /x\n",
    "FROM numericaloj-vibehub-runtime:1\nRUN true\nCOPY . /app\nCMD [\"x\"]\n",
    "FROM numericaloj-vibehub-runtime:1\nUSER 0\nCOPY . /app\nCMD [\"x\"]\n",
    "FROM numericaloj-vibehub-runtime:1\nVOLUME [\"/data\"]\nCOPY . /app\nCMD [\"x\"]\n",
    "FROM numericaloj-vibehub-runtime:1\nONBUILD VOLUME /data\nCOPY . /app\nCMD [\"x\"]\n",
    "FROM numericaloj-vibehub-runtime:1 AS build\nCOPY . /app\nCMD [\"x\"]\n",
    "FROM numericaloj-vibehub-runtime:1\nCOPY . /usr/local/bin\nCMD [\"x\"]\n",
    "FROM numericaloj-vibehub-runtime:1\nCOPY --chown=0:0 . /app\nCMD [\"x\"]\n",
    "FROM numericaloj-vibehub-runtime:1\nCOPY --chmod=0777 . /app\nCMD [\"x\"]\n",
])
def test_build_rejects_external_or_privilege_widening_dockerfile(tmp_path, dockerfile):
    package = _write_package(tmp_path / "package", dockerfile)

    with pytest.raises(runtime.VibeHubPackageError):
        runtime.build_image(
            package,
            "numoj-vibehub:test",
            docker_client=runtime.DockerCLI(
                command_runner=lambda *_args, **_kwargs: pytest.fail(
                    "invalid Dockerfile must fail before Docker"
                )
            ),
        )


@pytest.mark.parametrize("copy_line", [
    "COPY --chown=65532:65532 . /app",
    'COPY --chown=65532:65532 ["app.py", "/app/app.py"]',
])
def test_dockerfile_allows_only_runtime_uid_chown_copy_flag(copy_line):
    assert runtime._dockerfile_base_images(
        "\n".join((
            "FROM numericaloj-vibehub-runtime:1",
            copy_line,
            'CMD ["python", "/app/app.py"]',
        )),
        [runtime.DEFAULT_BASE_IMAGE],
    ) == (runtime.DEFAULT_BASE_IMAGE,)


def test_runtime_args_use_default_docker_and_featured_resources_double(
    monkeypatch,
    short_tmp,
):
    manager = _manager(monkeypatch, short_tmp)
    runtime_id = "a" * 40

    standard = manager._container_args(
        runtime_id=runtime_id,
        image_id=_APP_ID,
        featured=False,
        data_volume="numoj-vh-data-" + manager.scope + "-project-1-public",
    )
    featured = manager._container_args(
        runtime_id=runtime_id,
        image_id=_APP_ID,
        featured=True,
        data_volume="numoj-vh-data-" + manager.scope + "-project-1-public",
    )

    for required in (
        "--network", "none", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges=true", "--user", "65532:65532",
        "--pull", "never", "--ipc", "none",
    ):
        assert required in standard
    assert "--runtime" not in standard
    assert standard[standard.index("--memory") + 1] == "4g"
    assert featured[featured.index("--memory") + 1] == "8g"
    assert standard[standard.index("--cpu-period") + 1] == "100000"
    assert standard[standard.index("--cpu-quota") + 1] == "200000"
    assert featured[featured.index("--cpu-period") + 1] == "100000"
    assert featured[featured.index("--cpu-quota") + 1] == "400000"
    assert "--cpus" not in standard
    assert "--cpus" not in featured
    assert standard[standard.index("--pids-limit") + 1] == "256"
    assert featured[featured.index("--pids-limit") + 1] == "512"
    assert standard[standard.index("--log-driver") + 1] == "none"
    assert "--read-only" not in standard
    assert standard[standard.index("--storage-opt") + 1] == str(
        "size=" + str(runtime.STANDARD_WRITABLE_BYTES)
    )
    assert "--log-opt" not in standard
    tmpfs_mounts = [
        standard[index + 1]
        for index, value in enumerate(standard)
        if value == "--tmpfs"
    ]
    assert any(value.startswith("/tmp:") for value in tmpfs_mounts)
    assert (
        "/run/vibehub:rw,nosuid,nodev,noexec,"
        "size=16777216,mode=0770,uid=65532,gid=65532"
    ) in tmpfs_mounts
    mount = standard[standard.index("--mount") + 1]
    assert mount.endswith("-project-1-public,target=/data")
    assert mount.startswith("type=volume,source=numoj-vh-data-")
    assert "--volume" not in standard
    assert "-v" not in standard
    assert not any(value in standard for value in ("-p", "--publish", "--privileged"))


def test_runtime_lease_exposes_only_container_internal_socket_path(monkeypatch, short_tmp):
    lease = _manager(monkeypatch, short_tmp).acquire(
        "demo@v1", "numoj-vibehub:demo"
    )

    assert lease.socket_path == Path("/run/vibehub/app.sock")
    assert not (short_tmp / "runtime" / "sessions").exists()


def test_storage_key_is_database_identity_and_channel_bound(monkeypatch, short_tmp):
    manager = _manager(monkeypatch, short_tmp)
    for value in ("demo-public", "project-0-public", "project-1-review", "../x"):
        with pytest.raises(runtime.VibeHubLeaseError, match="storage_key"):
            manager.acquire(
                "demo@v1", "numoj-vibehub:demo", storage_key=value,
            )


def test_data_volume_persists_after_container_recreation(monkeypatch, short_tmp):
    docker = _FakeDocker()
    manager = _manager(monkeypatch, short_tmp, docker=docker)

    first = manager.acquire("demo@v1", "numoj-vibehub:demo")
    first_mount = docker.run_commands[-1][docker.run_commands[-1].index("--mount") + 1]
    assert manager.release(first.token) is True
    second = manager.acquire("demo@v1", "numoj-vibehub:demo")
    second_mount = docker.run_commands[-1][docker.run_commands[-1].index("--mount") + 1]

    assert first.container_name == second.container_name
    assert first_mount == second_mount
    assert len(docker.data_volumes) == 1
    assert len(docker.data_write_checks) == 2


def test_shared_leases_start_once_and_last_release_immediately_removes_container(
    monkeypatch,
    short_tmp,
):
    docker = _FakeDocker()
    manager = _manager(monkeypatch, short_tmp, docker=docker)

    first = manager.acquire("demo@v1", "numoj-vibehub:demo")
    second = manager.acquire("demo@v1", "numoj-vibehub:demo")

    assert len(docker.run_commands) == 1
    state_text = manager.state_path.read_text(encoding="utf-8")
    assert first.token not in state_text
    assert second.token not in state_text
    assert stat.S_IMODE(manager.state_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(manager.runtime_root.stat().st_mode) == 0o700

    assert manager.release(first.token) is True
    assert docker.stopped == []
    assert manager.release(second.token) is True
    assert docker.stopped == [first.container_name]


def test_active_runtime_limit_is_global_but_allows_existing_runtime_reuse(
    monkeypatch,
    short_tmp,
):
    docker = _FakeDocker()
    first_worker = _manager(
        monkeypatch,
        short_tmp,
        docker=docker,
        max_active_runtimes=1,
    )
    first = first_worker.acquire("first@v1", "numoj-vibehub:first")
    second_worker = _manager(
        monkeypatch,
        short_tmp,
        docker=docker,
        max_active_runtimes=1,
    )

    with pytest.raises(runtime.VibeHubCapacityError, match="宿主上限"):
        second_worker.acquire("second@v1", "numoj-vibehub:second")

    shared = second_worker.acquire("first@v1", "numoj-vibehub:first")
    assert shared.container_name == first.container_name
    assert len(docker.run_commands) == 1
    assert len(second_worker._load_state()["runtimes"]) == 1

    assert first_worker.release(first.token) is True
    assert second_worker.release(shared.token) is True
    assert docker.stopped == [first.container_name]


def test_active_runtime_limit_reclaims_crash_orphan_before_new_start(
    monkeypatch,
    short_tmp,
):
    docker = _FakeDocker()
    manager = _manager(
        monkeypatch,
        short_tmp,
        docker=docker,
        max_active_runtimes=2,
    )
    manager.acquire("first@v1", "numoj-vibehub:first")
    orphan_runtime_id = "b" * 40
    orphan_name = manager._container_name(orphan_runtime_id)
    docker.orphans[orphan_name] = {
        runtime.MANAGED_CONTAINER_LABEL: "1",
        runtime.MANAGER_SCOPE_LABEL: manager.scope,
        runtime.RUNTIME_ID_LABEL: orphan_runtime_id,
    }
    docker.running.add(orphan_name)

    restarted_worker = _manager(
        monkeypatch,
        short_tmp,
        docker=docker,
        max_active_runtimes=2,
    )
    second = restarted_worker.acquire("second@v1", "numoj-vibehub:second")

    assert len(docker.run_commands) == 2
    assert orphan_name in docker.stopped
    assert second.container_name in docker.running


def test_slow_start_reservation_never_holds_global_state_lock(
    monkeypatch,
    short_tmp,
):
    docker = _FakeDocker()
    starter = _manager(monkeypatch, short_tmp, docker=docker)
    observer = _manager(monkeypatch, short_tmp, docker=docker)
    waiting = threading.Event()
    continue_start = threading.Event()
    result = {}

    def block_readiness(*_args, **_kwargs):
        waiting.set()
        assert continue_start.wait(2)

    monkeypatch.setattr(starter, "_wait_ready", block_readiness)

    def acquire_in_thread():
        try:
            result["lease"] = starter.acquire(
                "slow@v1", "numoj-vibehub:slow"
            )
        except Exception as exc:  # pragma: no cover - asserted below
            result["error"] = exc

    thread = threading.Thread(target=acquire_in_thread)
    thread.start()
    assert waiting.wait(1)

    began = time.monotonic()
    with observer._locked_state() as state:
        reservation = next(iter(state["runtimes"].values()))
        assert reservation["status"] == "starting"
    assert time.monotonic() - began < 0.25

    began = time.monotonic()
    with pytest.raises(runtime.VibeHubCapacityError, match="正在切换"):
        observer.acquire("slow@v1", "numoj-vibehub:slow")
    assert time.monotonic() - began < 0.5

    continue_start.set()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert "error" not in result
    assert result["lease"].container_name in docker.running


def test_slow_heartbeat_probe_never_blocks_release_lock(
    monkeypatch,
    short_tmp,
):
    docker = _FakeDocker()
    heartbeat_worker = _manager(monkeypatch, short_tmp, docker=docker)
    first = heartbeat_worker.acquire("demo@v1", "numoj-vibehub:demo")
    second = heartbeat_worker.acquire("demo@v1", "numoj-vibehub:demo")
    release_worker = _manager(monkeypatch, short_tmp, docker=docker)
    probing = threading.Event()
    continue_probe = threading.Event()
    result = {}

    def block_probe(*_args, **_kwargs):
        probing.set()
        assert continue_probe.wait(2)

    monkeypatch.setattr(heartbeat_worker, "_probe_runtime_health", block_probe)

    def heartbeat_in_thread():
        try:
            result["lease"] = heartbeat_worker.heartbeat(first.token)
        except Exception as exc:  # pragma: no cover - asserted below
            result["error"] = exc

    thread = threading.Thread(target=heartbeat_in_thread)
    thread.start()
    assert probing.wait(1)

    began = time.monotonic()
    assert release_worker.release(second.token) is True
    assert time.monotonic() - began < 0.25

    continue_probe.set()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert "error" not in result
    assert result["lease"].container_name == first.container_name
    assert heartbeat_worker.release(first.token) is True


def test_busy_cross_process_health_probe_returns_capacity_without_renewal(
    monkeypatch,
    short_tmp,
):
    now = [100.0]
    docker = _FakeDocker()
    manager = _manager(
        monkeypatch,
        short_tmp,
        docker=docker,
        clock=lambda: now[0],
        health_probe_slot_timeout_seconds=0.05,
    )
    lease = manager.acquire("demo@v1", "numoj-vibehub:demo")
    digest = runtime._token_digest(lease.token)
    before = manager._load_state()["leases"][digest]["expires_at"]
    lock_names = [
        f"health-probe-slot-{index}.lock"
        for index in range(runtime.HEALTH_PROBE_CONCURRENCY)
    ]
    context = multiprocessing.get_context("fork")
    ready = context.Event()
    release = context.Event()
    process = context.Process(
        target=_hold_capacity_locks,
        args=(manager.runtime_root, lock_names, ready, release),
    )
    process.start()
    try:
        assert ready.wait(2)
        now[0] = 105.0
        with pytest.raises(runtime.VibeHubCapacityError, match="并发已满"):
            manager.heartbeat(lease.token)
        after = manager._load_state()["leases"][digest]["expires_at"]
        assert after == before
        assert lease.container_name in docker.running
    finally:
        release.set()
        process.join(timeout=2)
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
    assert process.exitcode == 0
    assert manager.release(lease.token) is True


def test_busy_health_probe_fails_new_start_fast_and_cleans_reservation(short_tmp):
    docker = _FakeDocker()
    manager = runtime.VibeHubRuntimeManager(
        short_tmp / "runtime",
        docker_client=docker,
        proxy_transport="docker-exec",
        health_probe_slot_timeout_seconds=0.05,
        clock=lambda: 100.0,
    )
    lock_names = [
        f"health-probe-slot-{index}.lock"
        for index in range(runtime.HEALTH_PROBE_CONCURRENCY)
    ]
    context = multiprocessing.get_context("fork")
    ready = context.Event()
    release = context.Event()
    process = context.Process(
        target=_hold_capacity_locks,
        args=(manager.runtime_root, lock_names, ready, release),
    )
    process.start()
    try:
        assert ready.wait(2)
        began = time.monotonic()
        with pytest.raises(runtime.VibeHubCapacityError, match="并发已满"):
            manager.acquire(
                "demo@v1", "numoj-vibehub:demo",
                storage_key="project-1-public",
            )
        assert time.monotonic() - began < 0.5
    finally:
        release.set()
        process.join(timeout=2)
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
    assert process.exitcode == 0
    assert manager._load_state() == runtime._empty_state()
    assert docker.running == set()


def test_expired_start_reservation_is_retried_and_cleaned_outside_lock(
    monkeypatch,
    short_tmp,
):
    docker = _FakeDocker()
    manager = _manager(monkeypatch, short_tmp, docker=docker, clock=lambda: 100.0)
    runtime_id = "c" * 40
    container_name = manager._container_name(runtime_id)
    with manager._locked_state() as state:
        state["runtimes"][runtime_id] = {
            "status": "starting",
            "reservation_id": "d" * 32,
            "reservation_deadline": 99.0,
            "container_name": container_name,
            "inflight": {},
        }
    docker.running.add(container_name)

    assert manager.reap_expired() >= 1

    assert docker.stopped == [container_name]
    assert manager._load_state()["runtimes"] == {}


def test_expired_lease_reaper_removes_container(monkeypatch, short_tmp):
    now = [100.0]
    docker = _FakeDocker()
    manager = _manager(
        monkeypatch,
        short_tmp,
        docker=docker,
        clock=lambda: now[0],
        lease_ttl_seconds=10,
    )
    lease = manager.acquire("demo@v1", "numoj-vibehub:demo")

    now[0] = 111.0
    assert manager.reap_expired() >= 1
    assert docker.stopped == [lease.container_name]


def test_background_reaper_collects_crashed_browser_without_later_request(
    monkeypatch,
    short_tmp,
):
    now = [100.0]
    docker = _FakeDocker()
    manager = _manager(
        monkeypatch,
        short_tmp,
        docker=docker,
        clock=lambda: now[0],
        lease_ttl_seconds=10,
        reaper_interval_seconds=0.05,
    )
    lease = manager.acquire("demo@v1", "numoj-vibehub:demo")
    now[0] = 111.0
    manager.start_reaper()
    try:
        deadline = time.monotonic() + 2
        while not docker.stopped and time.monotonic() < deadline:
            time.sleep(0.02)
        assert docker.stopped == [lease.container_name]
    finally:
        manager.stop_reaper()


def test_reconcile_only_removes_exactly_labeled_orphan(monkeypatch, short_tmp):
    docker = _FakeDocker()
    manager = _manager(monkeypatch, short_tmp, docker=docker)
    runtime_id = "b" * 40
    name = manager._container_name(runtime_id)
    docker.orphans[name] = {
        runtime.MANAGED_CONTAINER_LABEL: "1",
        runtime.MANAGER_SCOPE_LABEL: manager.scope,
        runtime.RUNTIME_ID_LABEL: runtime_id,
    }

    manager.reap_expired()

    assert docker.stopped == [name]


def test_proxy_overwrites_session_headers_and_strips_oj_credentials_and_cookies(
    monkeypatch,
    short_tmp,
):
    docker = _FakeDocker()
    manager = _manager(monkeypatch, short_tmp, docker=docker)
    first = manager.acquire("demo@v1", "numoj-vibehub:demo")
    second = manager.acquire("demo@v1", "numoj-vibehub:demo")
    observed: list[dict[str, str]] = []

    def fake_relay(_name, method, target, headers, body, **_kwargs):
        assert method == "POST"
        assert target == "/save?slot=1"
        assert body == b"payload"
        observed.append(dict(headers))
        return runtime.ProxyResponse(201, "Created", (
            ("Content-Type", "application/json"),
            ("Set-Cookie", "admin=true"),
            ("Access-Control-Allow-Origin", "*"),
            ("Connection", "X-Secret"),
            ("X-Secret", "drop-me"),
            ("Location", "/next"),
        ), b"{}")

    monkeypatch.setattr(docker, "relay_http", fake_relay)
    response = manager.proxy(
        first.token,
        "POST",
        "/save?slot=1",
        {
            "Content-Type": "application/json",
            "Cookie": "session=oj-admin",
            "Authorization": "Bearer secret",
            "X-CSRF-Token": "secret",
            "X-VibeHub-Base-Path": "/forged",
            "X-VibeHub-Session-Id": "forged",
        },
        b"payload",
        project_key="demo@v1",
        channel="public",
    )
    manager.proxy(second.token, "POST", "/save?slot=1", {}, b"payload")

    first_headers = {name.lower(): value for name, value in observed[0].items()}
    second_headers = {name.lower(): value for name, value in observed[1].items()}
    assert "cookie" not in first_headers
    assert "authorization" not in first_headers
    assert "x-csrf-token" not in first_headers
    assert first_headers["x-vibehub-base-path"] == first.proxy_base_path
    assert first_headers["x-vibehub-session-id"] != "forged"
    assert first_headers["x-vibehub-session-id"] != second_headers["x-vibehub-session-id"]

    response_headers = {name.lower(): value for name, value in response.headers}
    assert "set-cookie" not in response_headers
    assert response_headers["access-control-allow-origin"] == "null"
    assert response_headers["access-control-allow-methods"] == ", ".join(
        runtime.RUNTIME_CORS_METHODS
    )
    assert response_headers["access-control-allow-headers"] == ", ".join(
        runtime.RUNTIME_CORS_REQUEST_HEADERS
    )
    assert "x-secret" not in response_headers
    assert response_headers["location"] == first.proxy_base_path + "/next"
    assert "sandbox" in response_headers["content-security-policy"]


def test_stream_proxy_never_reads_body_for_invalid_token_or_full_capacity(
    monkeypatch,
    short_tmp,
):
    docker = _FakeDocker()
    manager = _manager(
        monkeypatch,
        short_tmp,
        docker=docker,
        proxy_slot_timeout_seconds=0,
    )
    reads = []

    def reader(limit):
        reads.append(limit)
        return b"payload"

    with pytest.raises(runtime.VibeHubLeaseError):
        manager.proxy_from_reader("invalid", "POST", "/", {}, reader)
    assert reads == []

    lease = manager.acquire("demo@v1", "numoj-vibehub:demo")

    @contextmanager
    def reject_capacity():
        raise runtime.VibeHubCapacityError("proxy full")
        yield  # pragma: no cover

    monkeypatch.setattr(manager, "_proxy_capacity_slot", reject_capacity)
    with pytest.raises(runtime.VibeHubCapacityError, match="proxy full"):
        manager.proxy_from_reader(lease.token, "POST", "/", {}, reader)
    assert reads == []


def test_stream_proxy_reads_once_inside_slot_and_enforces_body_limit(
    monkeypatch,
    short_tmp,
):
    docker = _FakeDocker()
    manager = _manager(monkeypatch, short_tmp, docker=docker)
    lease = manager.acquire("demo@v1", "numoj-vibehub:demo")
    in_slot = [False]
    reads = []

    @contextmanager
    def observe_capacity():
        in_slot[0] = True
        try:
            yield
        finally:
            in_slot[0] = False

    def oversized_reader(limit):
        assert in_slot[0] is True
        reads.append(limit)
        return b"x" * limit

    monkeypatch.setattr(manager, "_proxy_capacity_slot", observe_capacity)
    with pytest.raises(runtime.VibeHubRequestTooLarge):
        manager.proxy_from_reader(
            lease.token,
            "POST",
            "/",
            {},
            oversized_reader,
        )
    assert reads == [manager.request_max_bytes + 1]
    assert manager.release(lease.token) is True


def test_proxy_capability_validation_does_not_touch_docker_or_container_http(
    monkeypatch,
    short_tmp,
):
    docker = _FakeDocker()
    manager = _manager(monkeypatch, short_tmp, docker=docker)
    lease = manager.acquire("demo@v1", "numoj-vibehub:demo")
    docker.run_commands.clear()

    with monkeypatch.context() as isolated:
        isolated.setattr(
            manager,
            "_reconcile_once",
            lambda: pytest.fail("CORS 预检不得触发 Docker reconcile"),
        )
        isolated.setattr(
            manager,
            "_runtime_http_request",
            lambda *_args, **_kwargs: pytest.fail("CORS 预检不得访问作品容器"),
        )

        manager.validate_proxy_capability(lease.token)

    assert docker.run_commands == []
    assert docker.stopped == []
    assert manager.release(lease.token) is True


def test_invalid_proxy_headers_do_not_leave_inflight_request(monkeypatch, short_tmp):
    docker = _FakeDocker()
    manager = _manager(monkeypatch, short_tmp, docker=docker)
    lease = manager.acquire("demo@v1", "numoj-vibehub:demo")

    with pytest.raises(runtime.VibeHubProxyError, match="请求头格式"):
        manager.proxy(lease.token, "GET", "/", {"X-Bad": "a\nb"})

    assert manager.release(lease.token) is True
    assert docker.stopped == [lease.container_name]


def test_state_symlink_fails_closed(monkeypatch, short_tmp):
    manager = _manager(monkeypatch, short_tmp)
    outside = short_tmp / "outside.json"
    outside.write_text(json.dumps({"schema_version": 1, "runtimes": {}, "leases": {}}))
    manager.state_path.symlink_to(outside)

    with pytest.raises(runtime.VibeHubRuntimeError, match="state"):
        manager.reap_expired()


def test_composition_root_configuration_exposes_limits(short_tmp):
    runtime.shutdown_runtime_manager(reset_config=True)
    try:
        manager = runtime.configure_runtime_manager({
            "VIBEHUB_RUNTIME_ROOT": str(short_tmp / "configured"),
            "VIBEHUB_ALLOWED_BASE_IMAGES": ["local/base:locked"],
            "VIBEHUB_LEASE_TTL_SECONDS": 120,
            "VIBEHUB_REAPER_INTERVAL_SECONDS": 20,
            "VIBEHUB_REQUEST_TIMEOUT_SECONDS": 7,
            "VIBEHUB_REQUEST_MAX_BYTES": 1234,
            "VIBEHUB_RESPONSE_MAX_BYTES": 5678,
            "VIBEHUB_PROXY_TRANSPORT": "docker-exec",
            "VIBEHUB_BUILD_TIMEOUT_SECONDS": 321,
            "VIBEHUB_BUILD_SLOT_TIMEOUT_SECONDS": 9,
            "VIBEHUB_PROXY_SLOT_TIMEOUT_SECONDS": 0.5,
            "VIBEHUB_HEALTH_PROBE_SLOT_TIMEOUT_SECONDS": 0.2,
            "VIBEHUB_MAX_ACTIVE_RUNTIMES": 12,
            "VIBEHUB_BUILD_CACHE_MAX_BYTES": 2 * runtime.GIB,
            "VIBEHUB_BASE_OCI_LAYOUT_ROOT": str(short_tmp / "base-oci"),
        }, docker_client=_FakeDocker(), start_reaper=False)

        assert runtime.get_runtime_manager() is manager
        assert manager.allowed_base_images == ("local/base:locked",)
        assert manager.lease_ttl_seconds == 120
        assert manager.reaper_interval_seconds == 20
        assert manager.request_max_bytes == 1234
        assert manager.response_max_bytes == 5678
        assert manager.proxy_transport == "docker-exec"
        assert manager.build_timeout_seconds == 321
        assert manager.build_slot_timeout_seconds == 9
        assert manager.proxy_slot_timeout_seconds == 0.5
        assert manager.health_probe_slot_timeout_seconds == 0.2
        assert manager.max_active_runtimes == 12
        assert manager.build_cache_max_bytes == 2 * runtime.GIB
        assert manager.base_oci_layout_root == (short_tmp / "base-oci").resolve()
    finally:
        runtime.shutdown_runtime_manager(reset_config=True)


@pytest.mark.parametrize("value", (0, 540.001, float("inf"), float("nan")))
def test_build_timeout_configuration_rejects_unsafe_values(short_tmp, value):
    with pytest.raises(ValueError, match="VIBEHUB_BUILD_TIMEOUT_SECONDS"):
        runtime._manager_kwargs_from_config({
            "VIBEHUB_RUNTIME_ROOT": str(short_tmp / "configured"),
            "VIBEHUB_BUILD_TIMEOUT_SECONDS": value,
        })


@pytest.mark.parametrize("value", (0, 65, True, 8.0, "8", None))
def test_active_runtime_limit_configuration_is_strict(short_tmp, value):
    with pytest.raises(ValueError, match="VIBEHUB_MAX_ACTIVE_RUNTIMES"):
        runtime._manager_kwargs_from_config({
            "VIBEHUB_RUNTIME_ROOT": str(short_tmp / "configured"),
            "VIBEHUB_MAX_ACTIVE_RUNTIMES": value,
        })


def test_active_runtime_limit_default_and_maximum(short_tmp):
    defaults = runtime._manager_kwargs_from_config({
        "VIBEHUB_RUNTIME_ROOT": str(short_tmp / "default"),
    })
    maximum = runtime._manager_kwargs_from_config({
        "VIBEHUB_RUNTIME_ROOT": str(short_tmp / "maximum"),
        "VIBEHUB_MAX_ACTIVE_RUNTIMES": 64,
    })

    assert defaults["max_active_runtimes"] == 8
    assert maximum["max_active_runtimes"] == 64


@pytest.mark.parametrize("value", (0, 1, "true", None))
def test_required_builder_configuration_is_strict_boolean(short_tmp, value):
    with pytest.raises(ValueError, match="VIBEHUB_REQUIRE_DEDICATED_BUILDER"):
        runtime._manager_kwargs_from_config({
            "VIBEHUB_RUNTIME_ROOT": str(short_tmp / "configured"),
            "VIBEHUB_REQUIRE_DEDICATED_BUILDER": value,
        })


@pytest.mark.parametrize("value", (0, 256 * 1024 * 1024 - 1, True, "1"))
def test_build_cache_limit_configuration_is_strict(short_tmp, value):
    with pytest.raises(ValueError, match="VIBEHUB_BUILD_CACHE_MAX_BYTES"):
        runtime._manager_kwargs_from_config({
            "VIBEHUB_RUNTIME_ROOT": str(short_tmp / "configured"),
            "VIBEHUB_BUILD_CACHE_MAX_BYTES": value,
        })


def test_development_allows_legacy_builder(short_tmp):
    kwargs = runtime._manager_kwargs_from_config({
        "NUMOJ_ENVIRONMENT": "development",
        "VIBEHUB_RUNTIME_ROOT": str(short_tmp / "configured"),
        "VIBEHUB_BUILD_BUILDER": "",
        "VIBEHUB_REQUIRE_DEDICATED_BUILDER": False,
    })

    assert kwargs["build_builder"] == ""
    assert kwargs["require_dedicated_builder"] is False


def test_production_requires_dedicated_builder(short_tmp):
    base = {
        "NUMOJ_ENVIRONMENT": "production",
        "VIBEHUB_RUNTIME_ROOT": str(short_tmp / "configured"),
    }
    with pytest.raises(ValueError, match="专属 docker-container builder"):
        runtime._manager_kwargs_from_config(base)

    kwargs = runtime._manager_kwargs_from_config({
        **base,
        "VIBEHUB_BUILD_BUILDER": "numoj-vibehub",
        "VIBEHUB_REQUIRE_DEDICATED_BUILDER": True,
        "VIBEHUB_BASE_OCI_LAYOUT_ROOT": str(short_tmp / "base-oci"),
    })
    assert kwargs["build_builder"] == "numoj-vibehub"


def test_build_timeout_default_and_hard_cap_stay_below_gunicorn(short_tmp):
    kwargs = runtime._manager_kwargs_from_config({
        "VIBEHUB_RUNTIME_ROOT": str(short_tmp / "configured"),
    })

    assert kwargs["build_timeout_seconds"] == 480
    assert runtime.DEFAULT_BUILD_TIMEOUT_SECONDS == 480
    assert runtime.MAX_BUILD_TIMEOUT_SECONDS == 540
    assert runtime.MAX_BUILD_TIMEOUT_SECONDS < 600


def test_manager_passes_configured_build_timeout_to_builder(monkeypatch, short_tmp):
    package = _write_package(short_tmp / "package")
    manager = _manager(monkeypatch, short_tmp, build_timeout_seconds=321)
    observed = {}
    expected_digest = runtime._effective_source_digest(
        runtime._scan_context(package)[0],
        ((runtime.DEFAULT_BASE_IMAGE, _APP_ID),),
    )

    def fake_build_image(*_args, **kwargs):
        observed.update(kwargs)
        manager.docker.inspect_image = lambda reference: runtime.ImageInfo(
            str(reference),
            _APP_ID,
            1024,
            {
                runtime.MANAGED_IMAGE_LABEL: "1",
                runtime.SOURCE_DIGEST_LABEL: expected_digest,
            },
        )

    monkeypatch.setattr(runtime, "build_image", fake_build_image)

    manager._ensure_image(
        "numoj-vibehub:test",
        build_context=package,
        featured=False,
    )

    assert observed["timeout_seconds"] == 321


def test_low_level_builder_rejects_timeout_over_hard_cap(tmp_path):
    calls = []

    def runner(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("超限配置不应调用 Docker")

    with pytest.raises(ValueError, match="VIBEHUB_BUILD_TIMEOUT_SECONDS"):
        runtime.DockerCLI(command_runner=runner).build(
            tmp_path,
            "numoj-vibehub:test",
            source_digest="a" * 64,
            limits=runtime.limits_for(False),
            timeout=541,
        )
    assert calls == []


def test_registered_config_is_lazy_until_first_runtime_request(short_tmp):
    root = short_tmp / "lazy-runtime"
    runtime.shutdown_runtime_manager(reset_config=True)
    try:
        runtime.register_runtime_manager_config({
            "VIBEHUB_RUNTIME_ROOT": str(root),
            "VIBEHUB_ALLOWED_BASE_IMAGES": [runtime.DEFAULT_BASE_IMAGE],
            "VIBEHUB_LEASE_TTL_SECONDS": 90,
            "VIBEHUB_REAPER_INTERVAL_SECONDS": 15,
            "VIBEHUB_REQUEST_TIMEOUT_SECONDS": 15,
            "VIBEHUB_REQUEST_MAX_BYTES": 1024,
            "VIBEHUB_RESPONSE_MAX_BYTES": 2048,
        })
        assert not root.exists()

        manager = runtime.get_runtime_manager()
        assert manager.runtime_root == root.resolve()
        assert manager.proxy_transport == "docker-exec"
        assert root.is_dir()
        assert manager._reaper_thread is not None
    finally:
        runtime.shutdown_runtime_manager(reset_config=True)


def test_explicit_web_startup_ensures_reaper_idempotently(short_tmp):
    runtime.shutdown_runtime_manager(reset_config=True)
    try:
        manager = runtime.configure_runtime_manager(
            {
                "VIBEHUB_RUNTIME_ROOT": str(short_tmp / "web-runtime"),
                "VIBEHUB_PROXY_TRANSPORT": "docker-exec",
            },
            docker_client=_FakeDocker(),
            start_reaper=False,
        )
        assert manager._reaper_thread is None

        assert runtime.ensure_vibehub_runtime_reaper() is manager
        first_thread = manager._reaper_thread
        assert first_thread is not None and first_thread.is_alive()

        assert runtime.ensure_vibehub_runtime_reaper() is manager
        assert manager._reaper_thread is first_thread
    finally:
        runtime.shutdown_runtime_manager(reset_config=True)


def test_image_inspect_parses_and_fails_closed_on_volumes():
    def valid_runner(command, *, timeout, env=None):
        return runtime._CommandResult(0, json.dumps({
            "Id": _APP_ID,
            "Size": 123,
            "Config": {"Labels": {}, "Volumes": {"/data": {}}},
        }), "")

    image = runtime.DockerCLI(command_runner=valid_runner).inspect_image("local/app:1")
    assert image.volumes == ("/data",)

    def malformed_runner(command, *, timeout, env=None):
        return runtime._CommandResult(0, json.dumps({
            "Id": _APP_ID,
            "Size": 123,
            "Config": {"Labels": {}, "Volumes": ["/data"]},
        }), "")

    with pytest.raises(runtime.VibeHubImageError, match="inspect"):
        runtime.DockerCLI(command_runner=malformed_runner).inspect_image("local/app:1")


def test_data_volume_creation_is_labeled_and_existing_identity_is_verified():
    scope = "a" * 16
    name = f"numoj-vh-data-{scope}-project-42-public"
    calls = []
    payload = json.dumps({
        "Name": name,
        "Driver": "local",
        "Scope": "local",
        "Labels": {
            runtime.MANAGED_DATA_VOLUME_LABEL: "1",
            runtime.MANAGER_SCOPE_LABEL: scope,
            runtime.DATA_STORAGE_KEY_LABEL: "project-42-public",
        },
        "Options": None,
    })

    def runner(command, *, timeout, env=None):
        calls.append(list(command))
        if command[:3] == ["docker", "volume", "create"]:
            return runtime._CommandResult(0, name + "\n", "")
        return runtime._CommandResult(0, payload, "")

    docker = runtime.DockerCLI(command_runner=runner)
    docker.ensure_data_volume(
        name, scope=scope, storage_key="project-42-public",
    )

    create = calls[0]
    assert {create[index + 1] for index, value in enumerate(create) if value == "--label"} == {
        f"{runtime.MANAGED_DATA_VOLUME_LABEL}=1",
        f"{runtime.MANAGER_SCOPE_LABEL}={scope}",
        f"{runtime.DATA_STORAGE_KEY_LABEL}=project-42-public",
    }
    foreign = payload.replace(f'"{runtime.MANAGER_SCOPE_LABEL}": "{scope}", ', "")
    def foreign_runner(command, **_kwargs):
        if command[:3] == ["docker", "volume", "create"]:
            return runtime._CommandResult(0, name + "\n", "")
        return runtime._CommandResult(0, foreign, "")

    with pytest.raises(runtime.VibeHubRuntimeError, match="身份"):
        runtime.DockerCLI(command_runner=foreign_runner).ensure_data_volume(
            name, scope=scope, storage_key="project-42-public",
        )


def test_build_rejects_inherited_base_volume_before_docker_build(tmp_path):
    package = _write_package(tmp_path / "package")

    class VolumeBaseDocker(_FakeDocker):
        def inspect_image(self, reference):
            return runtime.ImageInfo(
                str(reference), _BASE_ID, 1024, {}, ("/host-data",),
            )

        def build(self, *_args, **_kwargs):
            pytest.fail("带 VOLUME 的基础镜像必须在 build 前拒绝")

    with pytest.raises(runtime.VibeHubImageError, match="基础镜像.*VOLUME"):
        runtime.build_image(package, "numoj-vibehub:test", docker_client=VolumeBaseDocker())


def test_cached_managed_image_with_volume_is_never_runnable(short_tmp):
    class CachedVolumeDocker(_FakeDocker):
        def inspect_image(self, reference):
            return runtime.ImageInfo(
                str(reference),
                _APP_ID,
                1024,
                {runtime.MANAGED_IMAGE_LABEL: "1"},
                ("/data",),
            )

    manager = runtime.VibeHubRuntimeManager(
        short_tmp / "runtime",
        docker_client=CachedVolumeDocker(),
        proxy_transport="docker-exec",
    )
    with pytest.raises(runtime.VibeHubImageError, match="VOLUME"):
        manager.acquire(
            "demo@v1", "numoj-vibehub:cached",
            storage_key="project-1-public",
        )


def test_project_image_tags_are_stable_per_live_channel():
    latest = runtime.image_reference_for("demo@v3", channel="latest")
    review = runtime.image_reference_for("demo@v3", channel="review")
    public = runtime.image_reference_for("demo@v3", channel="public")

    assert len({latest, review, public}) == 3
    assert runtime.image_reference_for("demo@v4", channel="latest") == latest
    assert runtime.image_reference_for("demo@v99", channel="review") == review
    assert runtime.image_reference_for("demo@v4", channel="public") == public
    assert runtime.image_reference_for("other@v3", channel="public") != public


def test_base_image_id_change_invalidates_cached_project_image(monkeypatch, tmp_path):
    package = _write_package(tmp_path / "package")
    base_ids = ["sha256:" + "3" * 64]
    context_digest = runtime._scan_context(package)[0]
    cached_digest = runtime._effective_source_digest(
        context_digest,
        ((runtime.DEFAULT_BASE_IMAGE, base_ids[0]),),
    )

    class CacheDocker(_FakeDocker):
        def __init__(self):
            super().__init__()
            self.project_digest = cached_digest
            self.builds = []

        def inspect_image(self, reference):
            if reference == runtime.DEFAULT_BASE_IMAGE:
                return runtime.ImageInfo(reference, base_ids[0], 1024, {})
            return runtime.ImageInfo(
                str(reference),
                _APP_ID,
                1024,
                {
                    runtime.MANAGED_IMAGE_LABEL: "1",
                    runtime.SOURCE_DIGEST_LABEL: self.project_digest,
                },
            )

        def build(self, _root, _ref, *, source_digest, **_kwargs):
            self.builds.append(source_digest)
            self.project_digest = source_digest

    docker = CacheDocker()
    manager = runtime.VibeHubRuntimeManager(
        tmp_path / "runtime",
        docker_client=docker,
        proxy_transport="docker-exec",
    )
    manager._ensure_image(
        "numoj-vibehub:demo", build_context=package, featured=False,
    )
    assert docker.builds == []

    base_ids[0] = "sha256:" + "4" * 64
    manager._ensure_image(
        "numoj-vibehub:demo", build_context=package, featured=False,
    )
    assert docker.builds == [runtime._effective_source_digest(
        context_digest,
        ((runtime.DEFAULT_BASE_IMAGE, base_ids[0]),),
    )]


def test_successful_build_cleanup_failure_leaves_marker_and_cached_retry(
    short_tmp,
):
    package = _write_package(short_tmp / "package")

    class CleanupDocker(_FakeDocker):
        def __init__(self):
            super().__init__()
            self.project_digest = None
            self.builds = 0
            self.fail_first_prune = True

        def inspect_image(self, reference):
            if reference == runtime.DEFAULT_BASE_IMAGE:
                return runtime.ImageInfo(reference, _BASE_ID, 1024, {})
            if self.project_digest is None:
                raise runtime.VibeHubImageError("not built")
            return runtime.ImageInfo(
                str(reference),
                _APP_ID,
                1024,
                {
                    runtime.MANAGED_IMAGE_LABEL: "1",
                    runtime.SOURCE_DIGEST_LABEL: self.project_digest,
                },
            )

        def build(self, _root, _ref, *, source_digest, **_kwargs):
            self.builds += 1
            self.project_digest = source_digest

        def prune_managed_dangling_images(self):
            self.managed_image_prunes += 1
            if self.fail_first_prune:
                self.fail_first_prune = False
                raise runtime.VibeHubImageError("prune failed")

    docker = CleanupDocker()
    manager = runtime.VibeHubRuntimeManager(
        short_tmp / "runtime",
        docker_client=docker,
        proxy_transport="docker-exec",
    )

    with pytest.raises(runtime.VibeHubImageError, match="prune failed"):
        manager._ensure_image(
            "numoj-vibehub:test",
            build_context=package,
            featured=False,
        )
    assert manager.build_cleanup_pending_path.is_file()

    image = manager._ensure_image(
        "numoj-vibehub:test",
        build_context=package,
        featured=False,
    )

    assert image.image_id == _APP_ID
    assert docker.builds == 1
    assert docker.managed_image_prunes == 2
    assert docker.build_cache_prunes == 1
    assert not manager.build_cleanup_pending_path.exists()


def test_last_release_reclaims_exact_idle_image_tag(monkeypatch, short_tmp):
    docker = _FakeDocker()
    manager = _manager(monkeypatch, short_tmp, docker=docker)
    lease = manager.acquire(
        "demo@v1",
        "numoj-vibehub:demo",
        channel="public",
    )

    assert manager.release(lease.token) is True

    assert docker.removed_image_references == [
        ("numoj-vibehub:demo", _APP_ID),
    ]
    assert docker.managed_image_prunes == 1
    assert manager._load_state()["runtimes"] == {}


def test_old_runtime_cleanup_cannot_delete_image_before_new_version_start(
    monkeypatch,
    short_tmp,
):
    docker = _FakeDocker()
    old_manager = _manager(monkeypatch, short_tmp, docker=docker)
    new_manager = _manager(monkeypatch, short_tmp, docker=docker)
    old_lease = old_manager.acquire(
        "demo@v1", "numoj-vibehub:demo", channel="public",
    )
    reserving = threading.Event()
    continue_reservation = threading.Event()
    acquire_result = {}
    release_result = {}
    original_capacity_check = new_manager._require_runtime_capacity_locked

    def block_before_reservation(state):
        reserving.set()
        assert continue_reservation.wait(2)
        original_capacity_check(state)

    monkeypatch.setattr(
        new_manager,
        "_require_runtime_capacity_locked",
        block_before_reservation,
    )

    def acquire_new_version():
        try:
            acquire_result["lease"] = new_manager.acquire(
                "demo@v2", "numoj-vibehub:demo", channel="public",
            )
        except Exception as exc:  # pragma: no cover - asserted below
            acquire_result["error"] = exc

    def release_old_version():
        try:
            release_result["released"] = old_manager.release(old_lease.token)
        except Exception as exc:  # pragma: no cover - asserted below
            release_result["error"] = exc

    acquire_thread = threading.Thread(target=acquire_new_version)
    acquire_thread.start()
    assert reserving.wait(1)
    release_thread = threading.Thread(target=release_old_version)
    release_thread.start()
    time.sleep(0.05)
    continue_reservation.set()
    acquire_thread.join(timeout=2)
    release_thread.join(timeout=2)

    assert not acquire_thread.is_alive()
    assert not release_thread.is_alive()
    assert "error" not in acquire_result
    assert "error" not in release_result
    assert release_result["released"] is True
    new_lease = acquire_result["lease"]
    assert new_lease.container_name in docker.running
    assert docker.removed_image_references == []

    assert new_manager.release(new_lease.token) is True
    assert docker.removed_image_references == [
        ("numoj-vibehub:demo", _APP_ID),
    ]


def test_idle_image_cleanup_failure_keeps_stopping_tombstone_for_retry(
    monkeypatch,
    short_tmp,
):
    class RetryDocker(_FakeDocker):
        def __init__(self):
            super().__init__()
            self.fail_first_prune = True

        def prune_managed_dangling_images(self):
            self.managed_image_prunes += 1
            if self.fail_first_prune:
                self.fail_first_prune = False
                raise runtime.VibeHubImageError("prune failed")

    docker = RetryDocker()
    manager = _manager(monkeypatch, short_tmp, docker=docker)
    lease = manager.acquire("demo@v1", "numoj-vibehub:demo")

    with pytest.raises(runtime.VibeHubImageError, match="prune failed"):
        manager.release(lease.token)
    state = manager._load_state()
    tombstone = next(iter(state["runtimes"].values()))
    assert tombstone["status"] == "stopping"
    assert state["leases"] == {}

    manager._clock = lambda: 200.0
    manager.reap_expired()

    assert manager._load_state()["runtimes"] == {}
    assert docker.managed_image_prunes == 2


def test_request_target_nfc_normalizes_unicode_and_preserves_valid_percent_encoding():
    target = runtime._safe_request_target("/cafe\u0301/猫?q=你好&slash=%2f&bad=%")
    assert target == (
        "/caf%C3%A9/%E7%8C%AB"
        "?q=%E4%BD%A0%E5%A5%BD&slash=%2F&bad=%25"
    )


@pytest.mark.parametrize(("location", "expected"), [
    ("/next?q=猫", "/vibehub/runtime/token/next?q=%E7%8C%AB"),
    ("child", "/vibehub/runtime/token/dir/child"),
    ("?slot=2", "/vibehub/runtime/token/dir/page?slot=2"),
    ("/vibehub/runtime/token/already", "/vibehub/runtime/token/already"),
])
def test_location_rewrite_handles_root_relative_query_and_existing_base(location, expected):
    response = runtime._sanitize_response(
        runtime.ProxyResponse(302, "Found", (
            ("Location", location),
            ("X-Untrusted", "drop"),
            ("Set-Cookie", "drop=1"),
        ), b""),
        base_path="/vibehub/runtime/token",
        request_target="/dir/page?old=1",
    )
    headers = dict(response.headers)
    assert headers["Location"] == expected
    assert "X-Untrusted" not in headers
    assert "Set-Cookie" not in headers


def test_location_rewrite_drops_external_redirect():
    response = runtime._sanitize_response(
        runtime.ProxyResponse(302, "Found", (("Location", "https://evil.test/x"),), b""),
        base_path="/vibehub/runtime/token",
        request_target="/",
    )
    assert "location" not in {name.lower() for name, _value in response.headers}


def _relay_frame(metadata, body=b""):
    encoded = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
    return runtime._RELAY_MAGIC + len(encoded).to_bytes(4, "big") + encoded + body


def test_relay_parser_rejects_1xx_bool_lengths_and_trailing_body():
    base = {
        "version": 1,
        "status": 200,
        "reason": "OK",
        "headers": [],
        "body_length": 0,
    }
    with pytest.raises(runtime.VibeHubProxyError):
        runtime._parse_relay_response(
            _relay_frame({**base, "status": 101}), response_max_bytes=1024,
        )
    with pytest.raises(runtime.VibeHubProxyError):
        runtime._parse_relay_response(
            _relay_frame({**base, "body_length": True}), response_max_bytes=1024,
        )
    with pytest.raises(runtime.VibeHubProxyError):
        runtime._parse_relay_response(
            _relay_frame(base, b"trailing"), response_max_bytes=1024,
        )


def test_host_uds_transport_is_rejected(short_tmp):
    runtime_root = short_tmp / "runtime"
    with pytest.raises(ValueError, match="host-uds 已禁用"):
        runtime.VibeHubRuntimeManager(
            runtime_root,
            docker_client=_FakeDocker(),
            proxy_transport="host-uds",
        )
    assert not runtime_root.exists()


def test_reconcile_preserves_other_worker_inflight(monkeypatch, short_tmp):
    docker = _FakeDocker()
    first = _manager(monkeypatch, short_tmp, docker=docker)
    lease = first.acquire("demo@v1", "numoj-vibehub:demo")
    with first._locked_state() as state:
        runtime_id = next(iter(state["runtimes"]))
        state["runtimes"][runtime_id]["inflight"]["worker-a"] = 200.0

    second = runtime.VibeHubRuntimeManager(
        first.runtime_root,
        docker_client=docker,
        clock=lambda: 100.0,
        proxy_transport="docker-exec",
    )
    second.reap_expired()
    state = second._load_state()
    assert state["runtimes"][runtime_id]["inflight"] == {"worker-a": 200.0}
    assert lease.container_name in docker.running


def test_proxy_transport_failure_destroys_runtime(monkeypatch, short_tmp):
    class RelayDocker(_FakeDocker):
        def relay_http(self, *_args, **_kwargs):
            raise runtime.VibeHubProxyError("bad relay frame")

    docker = RelayDocker()
    manager = _manager(
        monkeypatch,
        short_tmp,
        docker=docker,
        proxy_transport="docker-exec",
    )
    lease = manager.acquire("demo@v1", "numoj-vibehub:demo")

    with pytest.raises(runtime.VibeHubProxyError, match="bad relay"):
        manager.proxy(lease.token, "GET", "/", {})

    assert docker.stopped == [lease.container_name]
    state = manager._load_state()
    assert state["runtimes"] == {}
    assert state["leases"] == {}


def test_body_limit_hard_cap_is_enforced(short_tmp):
    with pytest.raises(ValueError, match="64 MiB"):
        runtime.VibeHubRuntimeManager(
            short_tmp / "runtime",
            docker_client=_FakeDocker(),
            proxy_transport="docker-exec",
            response_max_bytes=64 * 1024 * 1024 + 1,
        )


def test_docker_exec_relay_uses_fixed_bounded_command_and_frame():
    observed = {}

    def binary_runner(
        command,
        *,
        timeout,
        input_bytes,
        stdout_limit,
        stderr_limit,
    ):
        observed.update({
            "command": list(command),
            "timeout": timeout,
            "input": input_bytes,
            "stdout_limit": stdout_limit,
            "stderr_limit": stderr_limit,
        })
        frame = _relay_frame({
            "version": 1,
            "status": 200,
            "reason": "OK",
            "headers": [["Content-Type", "text/plain"]],
            "body_length": 2,
        }, b"ok")
        return runtime._BinaryCommandResult(0, frame, b"")

    docker = runtime.DockerCLI(binary_command_runner=binary_runner)
    name = "numoj-vh-" + "a" * 16 + "-" + "b" * 40
    response = docker.relay_http(
        name,
        "GET",
        "/%E7%8C%AB",
        {"Host": "vibehub.internal"},
        b"",
        timeout=2,
        response_max_bytes=1024,
    )

    assert response.body == b"ok"
    assert observed["command"] == [
        "docker", "exec", "-i", "--user", "65532:65532", name,
        "/usr/local/bin/vibehub-uds-relay",
    ]
    assert observed["stdout_limit"] == 1024 + runtime._RELAY_METADATA_MAX_BYTES + 8
    assert observed["stderr_limit"] == 16 * 1024
    assert observed["input"].startswith(runtime._RELAY_MAGIC)


def test_auto_transport_is_secure_alias_for_docker_exec(short_tmp):
    manager = runtime.VibeHubRuntimeManager(
        short_tmp / "runtime", docker_client=_FakeDocker(), proxy_transport="auto",
    )

    assert manager.proxy_transport == "docker-exec"


def test_heartbeat_requires_running_healthy_container(monkeypatch, short_tmp):
    docker = _FakeDocker()
    manager = _manager(monkeypatch, short_tmp, docker=docker)
    lease = manager.acquire("demo@v1", "numoj-vibehub:demo")
    monkeypatch.setattr(
        manager,
        "_probe_runtime_health",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            runtime.VibeHubProxyError("unhealthy")
        ),
    )

    with pytest.raises(runtime.VibeHubRuntimeError, match="健康检查失败"):
        manager.heartbeat(lease.token)

    assert docker.stopped == [lease.container_name]
    assert manager._load_state()["runtimes"] == {}


def test_build_process_slot_fails_fast_when_busy(tmp_path):
    package = _write_package(tmp_path / "package")
    assert runtime._PROCESS_BUILD_SEMAPHORE.acquire(timeout=0)
    try:
        with pytest.raises(runtime.VibeHubCapacityError, match="并发已满"):
            runtime.build_image(
                package,
                "numoj-vibehub:busy",
                docker_client=_FakeDocker(),
                slot_timeout_seconds=0,
            )
    finally:
        runtime._PROCESS_BUILD_SEMAPHORE.release()


def test_capacity_slots_are_shared_across_processes(short_tmp):
    manager = runtime.VibeHubRuntimeManager(
        short_tmp / "runtime",
        docker_client=_FakeDocker(),
        proxy_transport="docker-exec",
        build_slot_timeout_seconds=0.05,
        proxy_slot_timeout_seconds=0.05,
    )
    lock_names = ["build-slot-0.lock"] + [
        f"proxy-slot-{index}.lock" for index in range(runtime.PROXY_CONCURRENCY)
    ]
    context = multiprocessing.get_context("fork")
    ready = context.Event()
    release = context.Event()
    process = context.Process(
        target=_hold_capacity_locks,
        args=(manager.runtime_root, lock_names, ready, release),
    )
    process.start()
    try:
        assert ready.wait(2)
        with pytest.raises(runtime.VibeHubCapacityError):
            with manager._file_capacity_slot("build-slot", 1, 0.05):
                pytest.fail("跨进程 build lock 不应被重复取得")
        with pytest.raises(runtime.VibeHubCapacityError):
            with manager._file_capacity_slot(
                "proxy-slot", runtime.PROXY_CONCURRENCY, 0.05,
            ):
                pytest.fail("跨进程 proxy locks 不应被重复取得")
    finally:
        release.set()
        process.join(timeout=2)
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
    assert process.exitcode == 0
