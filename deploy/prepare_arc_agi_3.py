#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""准备生产运行所需的 ARC-AGI-3 公开游戏本地缓存。"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from typing import TextIO
from urllib.parse import quote
import uuid

from arcengine import ARCBaseGame, ActionInput, FrameDataRaw, GameAction
import numpy as np
from PIL import Image
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
_PALETTE = np.asarray(
    [
        (255, 255, 255),
        (204, 204, 204),
        (153, 153, 153),
        (102, 102, 102),
        (51, 51, 51),
        (0, 0, 0),
        (229, 58, 163),
        (255, 123, 204),
        (249, 60, 49),
        (30, 147, 255),
        (136, 216, 241),
        (255, 220, 0),
        (255, 133, 27),
        (146, 18, 49),
        (79, 204, 48),
        (163, 86, 214),
    ],
    dtype=np.uint8,
)


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
    response = session.get(
        f"{BASE_URL}{path}",
        headers={"Accept": accept},
        timeout=(10, 90),
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.is_redirect or response.is_permanent_redirect:
        raise ArcPublicSetError("ARC Prize API 返回了未预期的跳转。")
    declared_size = response.headers.get("Content-Length")
    if declared_size:
        try:
            if int(declared_size) > maximum_bytes:
                raise ArcPublicSetError("ARC Prize API 响应超过安全大小限制。")
        except ValueError as exc:
            raise ArcPublicSetError(
                "ARC Prize API 返回了无效的 Content-Length。"
            ) from exc
    content = response.content
    if len(content) > maximum_bytes:
        raise ArcPublicSetError("ARC Prize API 响应超过安全大小限制。")
    return content


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


def _load_game_class(
    source_path: Path,
    slug: str,
    version: str,
) -> type[ARCBaseGame]:
    module_spec = importlib.util.spec_from_file_location(
        f"numoj_arc_prepare_{slug}_{version}",
        source_path,
    )
    if module_spec is None or module_spec.loader is None:
        raise ArcPublicSetError(f"无法加载公开游戏：{slug}-{version}")
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    game_class = getattr(module, slug[0].upper() + slug[1:], None)
    if (
        not isinstance(game_class, type)
        or not issubclass(game_class, ARCBaseGame)
    ):
        raise ArcPublicSetError(f"公开游戏格式无效：{slug}-{version}")
    return game_class


def _input_details(actions: set[int]) -> tuple[str, str]:
    has_direction = bool(actions.intersection({1, 2, 3, 4}))
    has_action = 5 in actions
    has_click = 6 in actions
    if has_click and (has_direction or has_action):
        if has_direction:
            return "keyboard_click", "方向键 + 点击"
        return "keyboard_click", "操作键 + 点击"
    if has_click:
        return "click", "点击"
    if has_direction:
        return "keyboard", "方向键"
    if has_action:
        return "keyboard", "操作键"
    return "keyboard", "键盘"


def _validated_game_id(value: object) -> tuple[str, str, str]:
    if not isinstance(value, str) or value.count("-") != 1:
        raise ArcPublicSetError("ARC Prize API 返回了无效游戏标识。")
    slug, version = value.split("-", 1)
    if not _SLUG_PATTERN.fullmatch(slug):
        raise ArcPublicSetError("ARC Prize API 返回了无效游戏名称。")
    if not _VERSION_PATTERN.fullmatch(version):
        raise ArcPublicSetError("ARC Prize API 返回了无效游戏版本。")
    return value, slug, version


def _validate_cached_set(set_dir: Path, expected_count: int) -> dict:
    if not set_dir.is_dir() or not _SET_ID_PATTERN.fullmatch(set_dir.name):
        raise ArcPublicSetError("ARC-AGI-3 缓存目录名称无效。")
    manifest_path = set_dir / "manifest.json"
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArcPublicSetError("ARC-AGI-3 缓存清单无法读取。") from exc
    if payload.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ArcPublicSetError("ARC-AGI-3 缓存清单版本不受支持。")
    if payload.get("set_id") != set_dir.name:
        raise ArcPublicSetError("ARC-AGI-3 缓存指纹不匹配。")

    games = payload.get("games")
    if not isinstance(games, list) or len(games) != expected_count:
        raise ArcPublicSetError("ARC-AGI-3 缓存游戏数量不完整。")
    seen_slugs = set()
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
        preview_path = set_dir / "previews" / f"{slug}.png"
        if not source_path.is_file() or not preview_path.is_file():
            raise ArcPublicSetError(f"ARC-AGI-3 缓存文件缺失：{full_id}")
        source_digest = item.get("source_sha256")
        preview_digest = item.get("preview_sha256")
        if (
            not isinstance(source_digest, str)
            or not _SET_ID_PATTERN.fullmatch(source_digest)
            or _sha256_file(source_path) != source_digest
            or not isinstance(preview_digest, str)
            or not _SET_ID_PATTERN.fullmatch(preview_digest)
            or _sha256_file(preview_path) != preview_digest
        ):
            raise ArcPublicSetError(f"ARC-AGI-3 缓存哈希不匹配：{full_id}")
        with source_path.open("rb") as handle:
            if b"MIT License" not in handle.read(800):
                raise ArcPublicSetError(
                    f"ARC-AGI-3 缓存缺少 MIT 许可头：{full_id}"
                )
    return payload


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _find_reusable_set(
    data_root: Path,
    expected_count: int,
) -> Path | None:
    sets_root = (data_root / "sets").resolve()
    candidates = []
    current_link = data_root / "current"
    if current_link.is_symlink():
        try:
            current_target = current_link.resolve(strict=True)
        except OSError:
            current_target = None
        if current_target is not None and _is_within(current_target, sets_root):
            candidates.append(current_target)

    if sets_root.is_dir():
        other_sets = sorted(
            (
                path
                for path in sets_root.iterdir()
                if path.is_dir() and _SET_ID_PATTERN.fullmatch(path.name)
            ),
            key=lambda path: path.stat().st_mtime_ns,
            reverse=True,
        )
        candidates.extend(other_sets)

    seen = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        try:
            _validate_cached_set(resolved, expected_count)
        except ArcPublicSetError:
            continue
        return resolved
    return None


def _download_public_set(
    staging_root: Path,
    expected_count: int,
    *,
    output: TextIO,
) -> tuple[str, dict]:
    session = _build_http_session()
    try:
        anonymous = _get_json(session, "/api/games/anonkey")
        api_key = anonymous.get("api_key") if isinstance(anonymous, dict) else None
        if not isinstance(api_key, str) or not _API_KEY_PATTERN.fullmatch(api_key):
            raise ArcPublicSetError("ARC Prize API 未返回有效的匿名访问凭据。")
        session.headers["X-Api-Key"] = api_key

        listed_games = _get_json(session, "/api/games")
        if (
            not isinstance(listed_games, list)
            or len(listed_games) != expected_count
        ):
            actual_count = (
                len(listed_games) if isinstance(listed_games, list) else 0
            )
            raise ArcPublicSetError(
                "ARC-AGI-3 公开集数量不符合预期："
                f"预期 {expected_count}，实际 {actual_count}。"
            )
        game_ids = sorted(
            _validated_game_id(item.get("game_id"))[0]
            for item in listed_games
            if isinstance(item, dict)
        )
        if len(game_ids) != expected_count or len(set(game_ids)) != expected_count:
            raise ArcPublicSetError("ARC Prize API 游戏目录包含无效或重复条目。")

        environments_root = staging_root / "environments"
        previews_root = staging_root / "previews"
        environments_root.mkdir(mode=0o700)
        previews_root.mkdir(mode=0o700)
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

            try:
                game_class = _load_game_class(source_path, slug, version)
                signature = inspect.signature(game_class)
                kwargs = {"seed": 0} if "seed" in signature.parameters else {}
                game = game_class(**kwargs)
                frame_data = game.perform_action(
                    ActionInput(id=GameAction.RESET),
                    raw=True,
                )
            except ArcPublicSetError:
                raise
            except Exception as exc:
                raise ArcPublicSetError(
                    f"公开游戏初始化失败：{full_id}"
                ) from exc
            if not isinstance(frame_data, FrameDataRaw) or not frame_data.frame:
                raise ArcPublicSetError(
                    f"公开游戏没有生成有效初始画面：{full_id}"
                )
            frame = np.asarray(frame_data.frame[-1], dtype=np.int64)
            if (
                frame.ndim != 2
                or frame.size == 0
                or int(frame.min()) < 0
                or int(frame.max()) >= len(_PALETTE)
            ):
                raise ArcPublicSetError(
                    f"公开游戏初始画面颜色无效：{full_id}"
                )
            preview_path = previews_root / f"{slug}.png"
            Image.fromarray(_PALETTE[frame]).save(preview_path, format="PNG")
            preview_path.chmod(0o600)

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
            actions = {int(action) for action in frame_data.available_actions}
            input_kind, input_label = _input_details(actions)
            games.append(
                {
                    "slug": slug,
                    "version": version,
                    "full_id": full_id,
                    "title": title,
                    "default_fps": default_fps,
                    "level_count": len(baseline_actions),
                    "input_kind": input_kind,
                    "input_label": input_label,
                    "available_actions": sorted(actions),
                    "source_sha256": _sha256_bytes(source),
                    "preview_sha256": _sha256_file(preview_path),
                }
            )
            _show_progress(index, expected_count, full_id, output=output)
    finally:
        session.headers.pop("X-Api-Key", None)
        session.close()

    fingerprint_payload = json.dumps(
        games,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    set_id = _sha256_bytes(fingerprint_payload)
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "set_id": set_id,
        "source": BASE_URL,
        "game_count": len(games),
        "games": games,
    }
    _write_private_json(staging_root / "manifest.json", manifest)
    return set_id, manifest


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

    reusable = _find_reusable_set(data_root, expected_count)
    if reusable is not None:
        relative_target = f"sets/{reusable.name}"
        _show_progress(
            expected_count,
            expected_count,
            "本地缓存完整，跳过下载",
            output=output,
        )
        _write_result(result_file, relative_target)
        return relative_target

    staging_root = Path(
        tempfile.mkdtemp(prefix=".staging-", dir=data_root)
    )
    staging_root.chmod(0o700)
    try:
        set_id, _manifest = _download_public_set(
            staging_root,
            expected_count,
            output=output,
        )
        final_set = sets_root / set_id
        if final_set.exists():
            _validate_cached_set(final_set, expected_count)
        else:
            staging_root.rename(final_set)
        _validate_cached_set(final_set, expected_count)
        relative_target = f"sets/{set_id}"
        _write_result(result_file, relative_target)
        return relative_target
    finally:
        if staging_root.exists():
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
