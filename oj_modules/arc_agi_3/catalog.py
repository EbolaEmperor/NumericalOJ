#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""从部署缓存读取 ARC-AGI-3 公开游戏目录。"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import json
from pathlib import Path
import re


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_CURRENT_SET_LINK = _PROJECT_ROOT / ".deploy" / "arc-agi-3" / "current"
_SLUG_PATTERN = re.compile(r"^[a-z0-9]{4}$")
_VERSION_PATTERN = re.compile(r"^[0-9a-f]{8}$")


@dataclass(frozen=True)
class ArcGameSpec:
    slug: str
    version: str
    title: str
    default_fps: int
    level_count: int
    input_kind: str
    input_label: str
    data_root: Path

    @property
    def full_id(self):
        return f"{self.slug}-{self.version}"

    @property
    def class_name(self):
        return self.slug[0].upper() + self.slug[1:]

    @property
    def source_path(self):
        return (
            self.data_root
            / "environments"
            / self.slug
            / self.version
            / f"{self.slug}.py"
        )

    @property
    def preview_path(self):
        return self.data_root / "previews" / f"{self.slug}.png"

    def to_public_dict(self):
        return {
            "slug": self.slug,
            "full_id": self.full_id,
            "title": self.title,
            "default_fps": self.default_fps,
            "level_count": self.level_count,
            "input_kind": self.input_kind,
            "input_label": self.input_label,
        }


def _required_string(item, key):
    value = item.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"ARC-AGI-3 清单字段无效：{key}")
    return value


def _required_positive_int(item, key):
    value = item.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"ARC-AGI-3 清单字段无效：{key}")
    return value


@lru_cache(maxsize=4)
def _load_catalog(manifest_path_text, modified_ns, file_size):
    del modified_ns, file_size
    manifest_path = Path(manifest_path_text)
    data_root = manifest_path.parent
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise ValueError("ARC-AGI-3 部署清单版本不受支持。")

    raw_games = payload.get("games")
    if not isinstance(raw_games, list) or not raw_games:
        raise ValueError("ARC-AGI-3 部署清单没有游戏。")

    games = []
    seen_slugs = set()
    for item in raw_games:
        if not isinstance(item, dict):
            raise ValueError("ARC-AGI-3 游戏清单格式无效。")
        slug = _required_string(item, "slug")
        version = _required_string(item, "version")
        if not _SLUG_PATTERN.fullmatch(slug):
            raise ValueError("ARC-AGI-3 游戏标识无效。")
        if not _VERSION_PATTERN.fullmatch(version):
            raise ValueError("ARC-AGI-3 游戏版本无效。")
        if slug in seen_slugs:
            raise ValueError("ARC-AGI-3 游戏标识重复。")
        seen_slugs.add(slug)

        game = ArcGameSpec(
            slug=slug,
            version=version,
            title=_required_string(item, "title"),
            default_fps=_required_positive_int(item, "default_fps"),
            level_count=_required_positive_int(item, "level_count"),
            input_kind=_required_string(item, "input_kind"),
            input_label=_required_string(item, "input_label"),
            data_root=data_root,
        )
        if not game.source_path.is_file() or not game.preview_path.is_file():
            raise ValueError(f"ARC-AGI-3 游戏缓存不完整：{game.full_id}")
        games.append(game)

    return tuple(games)


def list_arc_games():
    try:
        manifest_path = (_CURRENT_SET_LINK / "manifest.json").resolve(strict=True)
        metadata = manifest_path.stat()
        return _load_catalog(
            str(manifest_path),
            metadata.st_mtime_ns,
            metadata.st_size,
        )
    except (OSError, ValueError, json.JSONDecodeError):
        return ()


def get_arc_game(game_id):
    normalized = str(game_id or "").strip().lower()
    return next(
        (game for game in list_arc_games() if game.slug == normalized),
        None,
    )
