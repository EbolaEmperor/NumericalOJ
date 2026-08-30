#!/usr/bin/env python3
"""Read-only preflight checks used by the in-place deployment entrypoint."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
MAX_ENV_FILE_BYTES = 1024 * 1024
REQUIRED_STRING_SETTINGS = (
    "SECRET_KEY",
    "MYSQL_HOST",
    "MYSQL_DB",
    "MYSQL_USERNAME",
    "MYSQL_PASSWORD",
    "REDIS_HOST",
)
REQUIRED_ENV_KEYS = REQUIRED_STRING_SETTINGS + (
    "MYSQL_PORT",
    "REDIS_PORT",
    "REDIS_DB",
)
SOURCE_DIGEST_DOMAIN = b"NumericalOJ Docker source v1\0"
REQUIRED_VIBEHUB_OCI_LAYOUT_ROOT = ROOT / ".deploy" / "vibehub-base-oci"
BUILDER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
BUILDER_NODE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
MAX_BUILDER_NODES = 16
VIBEHUB_BUILDKIT_IMAGE = (
    "moby/buildkit:v0.30.0@"
    "sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f"
)


class PreflightError(RuntimeError):
    """A deployment precondition failed without changing external state."""


def _load_project_config() -> ModuleType:
    """Import config lazily so unrelated preflight commands never load .env."""
    os.environ.setdefault("NUMOJ_ENVIRONMENT", "production")
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    return importlib.import_module("backend.oj_modules.config")


def _metadata_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_config_values(config: ModuleType) -> None:
    if not getattr(config, "ENV_FILE_LOADED", False):
        raise PreflightError("生产 .env 没有被配置模块加载")

    env_file_keys = getattr(config, "ENV_FILE_KEYS", ())
    try:
        missing = sorted(set(REQUIRED_ENV_KEYS) - set(env_file_keys))
    except TypeError as exc:
        raise PreflightError("生产 .env 的配置项清单无效") from exc
    if missing:
        raise PreflightError("生产 .env 缺少必填项: " + ", ".join(missing))

    for name in REQUIRED_STRING_SETTINGS:
        value = getattr(config, name, None)
        if not isinstance(value, str) or not value.strip():
            raise PreflightError(f"生产 .env 的必填字符串无效: {name}")

    for name in ("MYSQL_PORT", "REDIS_PORT"):
        value = getattr(config, name, None)
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 1 <= value <= 65535
        ):
            raise PreflightError(f"生产 .env 的端口无效: {name}")

    redis_db = getattr(config, "REDIS_DB", None)
    if not isinstance(redis_db, int) or isinstance(redis_db, bool) or redis_db < 0:
        raise PreflightError("生产 .env 的 REDIS_DB 无效")

    builder = getattr(config, "VIBEHUB_BUILD_BUILDER", None)
    if not isinstance(builder, str) or BUILDER_NAME_RE.fullmatch(builder) is None:
        raise PreflightError("生产 VibeHub 的 VIBEHUB_BUILD_BUILDER 无效")
    if getattr(config, "VIBEHUB_REQUIRE_DEDICATED_BUILDER", None) is not True:
        raise PreflightError("生产 VibeHub 必须要求专属 Buildx builder")

    layout_value = getattr(config, "VIBEHUB_BASE_OCI_LAYOUT_ROOT", None)
    if not isinstance(layout_value, str) or not layout_value.strip():
        raise PreflightError("生产 VibeHub 的 VIBEHUB_BASE_OCI_LAYOUT_ROOT 无效")
    layout_path = Path(layout_value)
    if ".." in layout_path.parts:
        raise PreflightError("VIBEHUB_BASE_OCI_LAYOUT_ROOT 路径无效")
    if not layout_path.is_absolute():
        layout_path = ROOT / layout_path
    if Path(os.path.abspath(layout_path)) != REQUIRED_VIBEHUB_OCI_LAYOUT_ROOT:
        raise PreflightError(
            "生产 VIBEHUB_BASE_OCI_LAYOUT_ROOT 必须指向项目内 "
            ".deploy/vibehub-base-oci"
        )


def validate_production_config(
    env_file: str | os.PathLike[str],
    *,
    config_loader: Callable[[], ModuleType] | None = None,
) -> None:
    """Validate the production .env metadata and its decoded settings."""
    path = Path(env_file)
    if path.is_symlink():
        raise PreflightError(f"生产配置不能是符号链接: {path}")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PreflightError(f"无法安全打开生产配置: {path}") from exc

    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if not stat.S_ISREG(metadata.st_mode):
            raise PreflightError(f"生产配置不是普通文件: {path}")
        if metadata.st_uid != os.geteuid():
            raise PreflightError(f"生产配置不属于当前部署用户: {path}")
        if mode not in (0o400, 0o600):
            raise PreflightError(
                f"生产配置权限必须是 0400 或 0600: {path} mode={mode:04o}"
            )
        if metadata.st_size > MAX_ENV_FILE_BYTES:
            raise PreflightError(f"生产配置文件异常过大: {path}")
        fingerprint = _metadata_fingerprint(metadata)

        loader = config_loader or _load_project_config
        config = loader()

        try:
            after = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise PreflightError("生产配置在校验过程中发生变化") from exc
        if not stat.S_ISREG(after.st_mode):
            raise PreflightError("生产配置在校验过程中发生变化")
        if _metadata_fingerprint(after) != fingerprint:
            raise PreflightError("生产配置在校验过程中发生变化")

        _validate_config_values(config)
    finally:
        os.close(descriptor)


def _run_builder_inspect(command_runner, command: list[str]):
    try:
        result = command_runner(
            command,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PreflightError("无法读取 VibeHub 专属 builder 状态") from exc
    if result.returncode != 0:
        raise PreflightError("VibeHub 专属 builder 状态读取失败")
    try:
        payload = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise PreflightError("VibeHub 专属 builder 状态格式无效") from exc
    if not isinstance(payload, dict):
        raise PreflightError("VibeHub 专属 builder 状态格式无效")
    return payload


def _read_buildx_builder(
    command_runner,
    builder: str,
    *,
    allow_missing: bool = False,
) -> dict | None:
    try:
        result = command_runner(
            ["docker", "buildx", "ls", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PreflightError("无法读取 VibeHub 专属 builder 清单") from exc
    if result.returncode != 0:
        detail = " ".join(str(result.stderr or "").split())[:300]
        suffix = f"：{detail}" if detail else ""
        raise PreflightError(
            f"VibeHub 专属 builder 清单读取失败（退出码：{result.returncode}）{suffix}"
        )
    try:
        payloads = [
            json.loads(line)
            for line in result.stdout.splitlines()
            if line.strip()
        ]
    except (TypeError, json.JSONDecodeError) as exc:
        raise PreflightError("VibeHub 专属 builder 清单格式无效") from exc
    if any(not isinstance(payload, dict) for payload in payloads):
        raise PreflightError("VibeHub 专属 builder 清单格式无效")
    matches = [payload for payload in payloads if payload.get("Name") == builder]
    if not matches:
        if allow_missing:
            return None
        raise PreflightError(f"生产未预置 VibeHub 专属 builder：{builder}")
    if len(matches) != 1:
        raise PreflightError("VibeHub 专属 builder 清单存在同名重复项")
    return matches[0]


def ensure_vibehub_builder(
    *,
    config_loader: Callable[[], ModuleType] | None = None,
    command_runner=None,
) -> str:
    """创建缺失的联网 builder，然后执行完整的只读校验。"""

    loader = config_loader or _load_project_config
    config = loader()
    builder = getattr(config, "VIBEHUB_BUILD_BUILDER", None)
    if not isinstance(builder, str) or BUILDER_NAME_RE.fullmatch(builder) is None:
        raise PreflightError("生产 VibeHub 专属 builder 名称无效")
    if getattr(config, "VIBEHUB_REQUIRE_DEDICATED_BUILDER", None) is not True:
        raise PreflightError(
            "生产 VibeHub 必须要求专属 docker-container builder"
        )

    runner = command_runner or subprocess.run
    if _read_buildx_builder(runner, builder, allow_missing=True) is None:
        node_name = f"{builder}0"
        if BUILDER_NODE_NAME_RE.fullmatch(node_name) is None:
            raise PreflightError("VibeHub 专属 builder 节点名称无效")
        command = [
            "docker", "buildx", "create",
            "--name", builder,
            "--node", node_name,
            "--driver", "docker-container",
            "--driver-opt", f"image={VIBEHUB_BUILDKIT_IMAGE}",
            "--driver-opt", "network=bridge",
            "--bootstrap",
            "default",
        ]
        try:
            result = runner(
                command,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise PreflightError("无法创建 VibeHub 专属 builder") from exc
        if result.returncode != 0:
            detail = " ".join(str(result.stderr or "").split())[:500]
            suffix = f"：{detail}" if detail else ""
            raise PreflightError(
                f"VibeHub 专属 builder 创建失败"
                f"（退出码：{result.returncode}）{suffix}"
            )
        print(f"已创建 VibeHub 专属 builder：{builder}", file=sys.stderr)

    return validate_vibehub_builder(
        config_loader=lambda: config,
        command_runner=runner,
    )


def validate_vibehub_builder(
    *,
    config_loader: Callable[[], ModuleType] | None = None,
    command_runner=None,
) -> str:
    """只读证明生产 Buildx builder 专属、可用且其所有节点可联网。"""

    loader = config_loader or _load_project_config
    config = loader()
    builder = getattr(config, "VIBEHUB_BUILD_BUILDER", None)
    if not isinstance(builder, str) or BUILDER_NAME_RE.fullmatch(builder) is None:
        raise PreflightError("生产 VibeHub 专属 builder 名称无效")
    if getattr(config, "VIBEHUB_REQUIRE_DEDICATED_BUILDER", None) is not True:
        raise PreflightError(
            "生产 VibeHub 必须要求专属 docker-container builder"
        )

    runner = command_runner or subprocess.run
    builder_payload = _read_buildx_builder(runner, builder)
    if (
        builder_payload.get("Name") != builder
        or builder_payload.get("Driver") != "docker-container"
    ):
        raise PreflightError(
            "生产 VibeHub builder 必须是同名 docker-container driver"
        )
    nodes = builder_payload.get("Nodes")
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= MAX_BUILDER_NODES:
        raise PreflightError("VibeHub 专属 builder 节点清单无效")

    seen_nodes: set[str] = set()
    for node in nodes:
        if not isinstance(node, dict):
            raise PreflightError("VibeHub 专属 builder 节点格式无效")
        node_name = node.get("Name")
        if (
            not isinstance(node_name, str)
            or BUILDER_NODE_NAME_RE.fullmatch(node_name) is None
            or node_name in seen_nodes
        ):
            raise PreflightError("VibeHub 专属 builder 节点名称无效")
        seen_nodes.add(node_name)
        if str(node.get("Status", "")).lower() != "running":
            raise PreflightError("VibeHub 专属 builder 存在未就绪节点")

        container_name = f"buildx_buildkit_{node_name}"
        container_payload = _run_builder_inspect(
            runner,
            [
                "docker",
                "container",
                "inspect",
                "--format",
                "{{json .}}",
                container_name,
            ],
        )
        if container_payload.get("Name") != f"/{container_name}":
            raise PreflightError("VibeHub builder 节点容器身份不匹配")
        state = container_payload.get("State")
        host_config = container_payload.get("HostConfig")
        if not isinstance(state, dict) or state.get("Running") is not True:
            raise PreflightError("VibeHub builder 节点容器未运行")
        if (
            not isinstance(host_config, dict)
            or host_config.get("NetworkMode") != "bridge"
        ):
            raise PreflightError(
                "VibeHub builder 节点容器必须使用 network=bridge"
            )
    return builder


def docker_source_digest(
    context: str | os.PathLike[str], inputs: Sequence[str]
) -> str:
    """Return the deployment source digest for explicit Docker build inputs."""
    root = Path(context)
    digest = hashlib.sha256(SOURCE_DIGEST_DOMAIN)
    for relative_name in inputs:
        relative = Path(relative_name)
        if (
            not relative_name
            or relative.is_absolute()
            or ".." in relative.parts
            or "\x00" in relative_name
        ):
            raise PreflightError(f"Docker 构建输入路径无效: {relative_name!r}")
        path = root / relative_name
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            if path.is_symlink():
                raise PreflightError(
                    f"Docker 构建输入必须是普通文件: {path}"
                ) from exc
            raise PreflightError(f"无法安全打开 Docker 构建输入: {path}") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise PreflightError(f"Docker 构建输入必须是普通文件: {path}")
            fingerprint = _metadata_fingerprint(metadata)
            encoded_name = relative_name.encode("utf-8")
            digest.update(len(encoded_name).to_bytes(8, "big"))
            digest.update(encoded_name)
            digest.update(stat.S_IMODE(metadata.st_mode).to_bytes(4, "big"))
            digest.update(metadata.st_size.to_bytes(8, "big"))
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
            after_fd = os.fstat(descriptor)
            try:
                after_path = path.stat(follow_symlinks=False)
            except OSError as exc:
                raise PreflightError(
                    f"Docker 构建输入在摘要过程中发生变化: {path}"
                ) from exc
            if (
                _metadata_fingerprint(after_fd) != fingerprint
                or _metadata_fingerprint(after_path) != fingerprint
            ):
                raise PreflightError(
                    f"Docker 构建输入在摘要过程中发生变化: {path}"
                )
        finally:
            os.close(descriptor)
    return digest.hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser(
        "validate-config", description="Validate the private production .env file."
    )
    validate.add_argument("env_file", type=Path)

    commands.add_parser(
        "validate-vibehub-builder",
        description="Validate the dedicated, network-isolated Buildx builder.",
    )
    commands.add_parser(
        "ensure-vibehub-builder",
        description="Create the dedicated Buildx builder when it is missing.",
    )

    source_digest = commands.add_parser(
        "docker-source-digest",
        description="Fingerprint explicit Docker build inputs.",
    )
    source_digest.add_argument("context", type=Path)
    source_digest.add_argument("inputs", nargs="+")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate-config":
            validate_production_config(args.env_file)
        elif args.command == "ensure-vibehub-builder":
            print(ensure_vibehub_builder())
        elif args.command == "validate-vibehub-builder":
            print(validate_vibehub_builder())
        else:
            print(docker_source_digest(args.context, args.inputs))
    except (OSError, PreflightError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
