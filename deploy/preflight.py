#!/usr/bin/env python3
"""Read-only preflight checks used by the in-place deployment entrypoint."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
import hashlib
import importlib
import os
from pathlib import Path
import stat
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


class PreflightError(RuntimeError):
    """A deployment precondition failed without changing external state."""


def _load_project_config() -> ModuleType:
    """Import config lazily so unrelated preflight commands never load .env."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    return importlib.import_module("config")


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
        raise PreflightError("生产 .env 没有被 config.py 加载")

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
        else:
            print(docker_source_digest(args.context, args.inputs))
    except (OSError, PreflightError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
