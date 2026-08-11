#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""准备生产运行所需的 ARC-AGI-3 公开游戏本地缓存。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
from typing import TextIO
from urllib.parse import quote
import uuid

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


BASE_URL = "https://three.arcprize.org"
MANIFEST_SCHEMA_VERSION = 1
DEFAULT_EXPECTED_COUNT = 25
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 64 * 1024 * 1024
_SLUG_PATTERN = re.compile(r"^[a-z0-9]{4}$")
_VERSION_PATTERN = re.compile(r"^[0-9a-f]{8}$")
_SET_ID_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_API_KEY_PATTERN = re.compile(r"^[A-Za-z0-9-]{16,128}$")
class ArcPublicSetError(RuntimeError):
    """公开集无法安全准备。"""


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_private_bytes(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    path.chmod(0o600)


def _write_private_json(path: Path, payload: object) -> None:
    content = (
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    _write_private_bytes(path, content)


def _progress_line(completed: int, total: int, label: str) -> str:
    width = 30
    filled = width if total <= 0 else round(width * completed / total)
    filled = max(0, min(width, filled))
    bar = "█" * filled + "░" * (width - filled)
    return f"[{bar}] {completed:02d}/{total:02d}  {label}"


def _show_progress(
    completed: int,
    total: int,
    label: str,
    *,
    output: TextIO = sys.stdout,
) -> None:
    interactive = bool(getattr(output, "isatty", lambda: False)())
    prefix = "\r" if interactive else ""
    suffix = "\n" if not interactive or completed >= total else ""
    output.write(f"{prefix}{_progress_line(completed, total, label)}{suffix}")
    output.flush()


def _build_http_session() -> requests.Session:
    retry = Retry(
        total=3,
        connect=3,
        read=3,
        status=3,
        backoff_factor=0.8,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        respect_retry_after_header=True,
    )
    session = requests.Session()
    session.headers.update(
        {
            "Accept": "application/json",
            "User-Agent": "NumericalOJ-ARC-AGI-3-deployer/1",
        }
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


def _get_content(
    session: requests.Session,
    path: str,
    *,
    maximum_bytes: int,
    accept: str,
) -> bytes:
    if maximum_bytes <= 0:
        raise ValueError("maximum_bytes 必须为正整数")
    response = session.get(
        f"{BASE_URL}{path}",
        headers={"Accept": accept},
        timeout=(10, 90),
        allow_redirects=False,
        stream=True,
    )
    try:
        response.raise_for_status()
        if response.is_redirect or response.is_permanent_redirect:
            raise ArcPublicSetError("ARC Prize API 返回了未预期的跳转。")
        declared_size = response.headers.get("Content-Length")
        if declared_size:
            try:
                parsed_size = int(declared_size)
                if parsed_size < 0 or parsed_size > maximum_bytes:
                    raise ArcPublicSetError("ARC Prize API 响应超过安全大小限制。")
            except ValueError as exc:
                raise ArcPublicSetError(
                    "ARC Prize API 返回了无效的 Content-Length。"
                ) from exc

        # ``stream=True`` 只阻止 requests 预先把响应整体载入内存；仍须按
        # 解压后的 chunk 实际长度累计，才能同时约束无 Content-Length、
        # 分块传输以及压缩响应。
        content = bytearray()
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            if len(chunk) > maximum_bytes - len(content):
                raise ArcPublicSetError("ARC Prize API 响应超过安全大小限制。")
            content.extend(chunk)
        return bytes(content)
    finally:
        response.close()


def _get_json(session: requests.Session, path: str) -> object:
    content = _get_content(
        session,
        path,
        maximum_bytes=MAX_JSON_BYTES,
        accept="application/json",
    )
    try:
        return json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArcPublicSetError("ARC Prize API 返回了无效 JSON。") from exc


def _validated_game_id(value: object) -> tuple[str, str, str]:
    if not isinstance(value, str) or value.count("-") != 1:
        raise ArcPublicSetError("ARC Prize API 返回了无效游戏标识。")
    slug, version = value.split("-", 1)
    if not _SLUG_PATTERN.fullmatch(slug):
        raise ArcPublicSetError("ARC Prize API 返回了无效游戏名称。")
    if not _VERSION_PATTERN.fullmatch(version):
        raise ArcPublicSetError("ARC Prize API 返回了无效游戏版本。")
    return value, slug, version


def _games_fingerprint(games: list[dict]) -> str:
    fingerprint_payload = json.dumps(
        games,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _sha256_bytes(fingerprint_payload)


def _validate_cached_set(
    set_dir: Path,
    expected_count: int,
    *,
    expected_set_id: str | None = None,
) -> dict:
    directory_set_id = expected_set_id or set_dir.name
    if (
        set_dir.is_symlink()
        or not set_dir.is_dir()
        or not _SET_ID_PATTERN.fullmatch(directory_set_id)
    ):
        raise ArcPublicSetError("ARC-AGI-3 缓存目录名称无效。")
    manifest_path = set_dir / "manifest.json"
    if (
        manifest_path.is_symlink()
        or not manifest_path.is_file()
        or manifest_path.stat().st_size > MAX_JSON_BYTES
    ):
        raise ArcPublicSetError("ARC-AGI-3 缓存清单无法读取。")
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArcPublicSetError("ARC-AGI-3 缓存清单无法读取。") from exc
    if payload.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ArcPublicSetError("ARC-AGI-3 缓存清单版本不受支持。")
    if payload.get("set_id") != directory_set_id:
        raise ArcPublicSetError("ARC-AGI-3 缓存指纹不匹配。")

    games = payload.get("games")
    if not isinstance(games, list) or len(games) != expected_count:
        raise ArcPublicSetError("ARC-AGI-3 缓存游戏数量不完整。")
    seen_slugs = set()
    expected_files = {Path("manifest.json")}
    expected_directories = {Path("environments")}
    for item in games:
        if not isinstance(item, dict):
            raise ArcPublicSetError("ARC-AGI-3 缓存游戏条目无效。")
        full_id, slug, version = _validated_game_id(item.get("full_id"))
        if (
            item.get("slug") != slug
            or item.get("version") != version
            or slug in seen_slugs
        ):
            raise ArcPublicSetError("ARC-AGI-3 缓存游戏条目不一致。")
        seen_slugs.add(slug)
        source_path = (
            set_dir / "environments" / slug / version / f"{slug}.py"
        )
        if (
            source_path.is_symlink()
            or not source_path.is_file()
        ):
            raise ArcPublicSetError(f"ARC-AGI-3 缓存文件缺失：{full_id}")
        expected_files.add(source_path.relative_to(set_dir))
        expected_directories.update(
            {
                Path("environments") / slug,
                Path("environments") / slug / version,
            }
        )
        source_digest = item.get("source_sha256")
        if (
            not isinstance(source_digest, str)
            or not _SET_ID_PATTERN.fullmatch(source_digest)
            or _sha256_file(source_path) != source_digest
        ):
            raise ArcPublicSetError(f"ARC-AGI-3 缓存哈希不匹配：{full_id}")
        with source_path.open("rb") as handle:
            if b"MIT License" not in handle.read(800):
                raise ArcPublicSetError(
                    f"ARC-AGI-3 缓存缺少 MIT 许可头：{full_id}"
                )
    if _games_fingerprint(games) != payload.get("set_id"):
        raise ArcPublicSetError("ARC-AGI-3 缓存内容指纹不匹配。")
    actual_files = set()
    actual_directories = set()
    for path in set_dir.rglob("*"):
        relative = path.relative_to(set_dir)
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ArcPublicSetError(f"ARC-AGI-3 缓存不得包含符号链接：{relative}")
        if stat.S_ISREG(metadata.st_mode):
            actual_files.add(relative)
        elif stat.S_ISDIR(metadata.st_mode):
            actual_directories.add(relative)
        else:
            raise ArcPublicSetError(f"ARC-AGI-3 缓存包含特殊文件：{relative}")
    if actual_files != expected_files or actual_directories != expected_directories:
        raise ArcPublicSetError("ARC-AGI-3 缓存包含未声明或缺失的路径。")
    return payload


def _fetch_public_catalog(
    session: requests.Session,
    expected_count: int,
) -> tuple[str, ...]:
    """每次部署都读取官方线上目录；异常时 fail-closed。"""
    anonymous = _get_json(session, "/api/games/anonkey")
    api_key = anonymous.get("api_key") if isinstance(anonymous, dict) else None
    if not isinstance(api_key, str) or not _API_KEY_PATTERN.fullmatch(api_key):
        raise ArcPublicSetError("ARC Prize API 未返回有效的匿名访问凭据。")
    session.headers["X-Api-Key"] = api_key

    listed_games = _get_json(session, "/api/games")
    if not isinstance(listed_games, list) or len(listed_games) != expected_count:
        actual_count = len(listed_games) if isinstance(listed_games, list) else 0
        raise ArcPublicSetError(
            "ARC-AGI-3 公开集数量不符合预期："
            f"预期 {expected_count}，实际 {actual_count}。"
        )
    validated_ids = [
        _validated_game_id(item.get("game_id"))
        for item in listed_games
        if isinstance(item, dict)
    ]
    game_ids = tuple(sorted(item[0] for item in validated_ids))
    slugs = {item[1] for item in validated_ids}
    if (
        len(game_ids) != expected_count
        or len(set(game_ids)) != expected_count
        or len(slugs) != expected_count
    ):
        raise ArcPublicSetError("ARC Prize API 游戏目录包含无效或重复条目。")
    return game_ids


def _download_public_set(
    staging_root: Path,
    expected_count: int,
    *,
    output: TextIO,
    session: requests.Session | None = None,
    game_ids: tuple[str, ...] | None = None,
) -> str:
    owns_session = session is None
    session = session or _build_http_session()
    try:
        game_ids = game_ids or _fetch_public_catalog(session, expected_count)

        environments_root = staging_root / "environments"
        environments_root.mkdir(mode=0o700)
        games = []
        total_source_bytes = 0
        _show_progress(0, expected_count, "准备下载", output=output)

        for index, full_id in enumerate(game_ids, start=1):
            _, slug, version = _validated_game_id(full_id)
            metadata = _get_json(
                session,
                f"/api/games/{quote(slug, safe='')}",
            )
            if not isinstance(metadata, dict):
                raise ArcPublicSetError(f"公开游戏元数据无效：{full_id}")
            if metadata.get("game_id") != full_id:
                raise ArcPublicSetError(f"下载过程中游戏版本发生变化：{slug}")

            source = _get_content(
                session,
                f"/api/games/{quote(full_id, safe='')}/source",
                maximum_bytes=MAX_SOURCE_BYTES,
                accept="text/plain",
            )
            total_source_bytes += len(source)
            if total_source_bytes > MAX_TOTAL_SOURCE_BYTES:
                raise ArcPublicSetError("ARC-AGI-3 公开集源码总量超过安全限制。")
            try:
                source.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ArcPublicSetError(f"公开游戏源码不是 UTF-8：{full_id}") from exc
            if b"MIT License" not in source[:800]:
                raise ArcPublicSetError(f"公开游戏缺少 MIT 许可头：{full_id}")

            environment_dir = environments_root / slug / version
            environment_dir.mkdir(parents=True, mode=0o700)
            source_path = environment_dir / f"{slug}.py"
            _write_private_bytes(source_path, source)

            title = metadata.get("title")
            default_fps = metadata.get("default_fps")
            baseline_actions = metadata.get("baseline_actions")
            if (
                not isinstance(title, str)
                or not title
                or len(title) > 80
                or isinstance(default_fps, bool)
                or not isinstance(default_fps, int)
                or not 1 <= default_fps <= 240
                or not isinstance(baseline_actions, list)
                or not baseline_actions
            ):
                raise ArcPublicSetError(f"公开游戏元数据字段无效：{full_id}")
            games.append(
                {
                    "slug": slug,
                    "version": version,
                    "full_id": full_id,
                    "title": title,
                    "default_fps": default_fps,
                    "level_count": len(baseline_actions),
                    "source_sha256": _sha256_bytes(source),
                }
            )
            _show_progress(index, expected_count, full_id, output=output)
    finally:
        if owns_session:
            session.headers.pop("X-Api-Key", None)
            session.close()

    set_id = _games_fingerprint(games)
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "set_id": set_id,
        "games": games,
    }
    _write_private_json(staging_root / "manifest.json", manifest)
    return set_id


def _write_result(result_file: Path, relative_target: str) -> None:
    result_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = result_file.with_name(
        f".{result_file.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
    )
    try:
        _write_private_bytes(
            temporary,
            f"{relative_target}\n".encode("ascii"),
        )
        os.replace(temporary, result_file)
    finally:
        temporary.unlink(missing_ok=True)


def prepare_public_set(
    data_root: Path,
    result_file: Path,
    expected_count: int = DEFAULT_EXPECTED_COUNT,
    *,
    output: TextIO = sys.stdout,
) -> str:
    data_root = data_root.resolve()
    data_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    sets_root = data_root / "sets"
    sets_root.mkdir(mode=0o700, exist_ok=True)

    session = _build_http_session()
    try:
        official_game_ids = _fetch_public_catalog(session, expected_count)
        staging_root = Path(
            tempfile.mkdtemp(prefix=".staging-", dir=data_root)
        )
        staging_root.chmod(0o700)
        set_id = _download_public_set(
            staging_root,
            expected_count,
            output=output,
            session=session,
            game_ids=official_game_ids,
        )
        _validate_cached_set(
            staging_root,
            expected_count,
            expected_set_id=set_id,
        )
        final_set = sets_root / set_id
        if final_set.exists():
            try:
                _validate_cached_set(final_set, expected_count)
            except ArcPublicSetError:
                quarantine = sets_root / f".{set_id}.corrupt-{uuid.uuid4().hex}"
                os.replace(final_set, quarantine)
                try:
                    os.replace(staging_root, final_set)
                    _validate_cached_set(final_set, expected_count)
                except Exception:
                    if final_set.exists():
                        shutil.rmtree(final_set, ignore_errors=True)
                    os.replace(quarantine, final_set)
                    raise
                shutil.rmtree(quarantine)
            else:
                _show_progress(
                    expected_count,
                    expected_count,
                    "线上内容哈希一致，复用本地完整缓存",
                    output=output,
                )
        else:
            os.replace(staging_root, final_set)
        _validate_cached_set(final_set, expected_count)
        relative_target = f"sets/{set_id}"
        _write_result(result_file, relative_target)
        return relative_target
    finally:
        session.headers.pop("X-Api-Key", None)
        session.close()
        if "staging_root" in locals() and staging_root.exists():
            shutil.rmtree(staging_root)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="下载并校验 ARC-AGI-3 公开游戏部署缓存。",
    )
    parser.add_argument("--data-root", required=True, type=Path)
    parser.add_argument("--result-file", required=True, type=Path)
    parser.add_argument(
        "--expected-count",
        type=int,
        default=DEFAULT_EXPECTED_COUNT,
    )
    args = parser.parse_args(argv)
    if args.expected_count <= 0 or args.expected_count > 1000:
        parser.error("--expected-count 必须位于 1 到 1000 之间")
    return args


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        target = prepare_public_set(
            args.data_root,
            args.result_file,
            args.expected_count,
        )
    except (ArcPublicSetError, OSError, requests.RequestException) as exc:
        print(f"ARC-AGI-3 公开集准备失败：{exc}", file=sys.stderr)
        return 1
    print(f"ARC-AGI-3 公开集已准备：{target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
