#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lean 4 多文件题目包的解析与规范化。"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re

from backend.oj_modules.shared.archive import (
    ArchiveExtractionError,
    ZipExtractionPolicy,
    extract_zip,
)


MANIFEST_FILENAME = "numoj-lean.json"
LEAN_PACKAGE_SCHEMA_VERSION = 1
MAX_LEAN_FILES = 64
MAX_LEAN_FILE_BYTES = 1024 * 1024
MAX_LEAN_TOTAL_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 128 * 1024
DEFAULT_PERMITTED_AXIOMS = (
    "propext",
    "Quot.sound",
    "Classical.choice",
)

_DECLARATION_NAME_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*$"
)
_PATH_PART_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_']*$")
_RESERVED_WRITABLE_ROOTS = frozenset(
    {"Init", "Lean", "Std", "Mathlib", "Batteries", "Lake"}
)


class LeanPackageError(ValueError):
    """Lean 题目包不符合 v1 契约。"""


@dataclass(frozen=True)
class LeanPackageFile:
    path: str
    mode: str
    order: int
    content: str
    content_sha256: str
    size_bytes: int

    @property
    def module(self) -> str:
        return self.path[:-5].replace("/", ".")

    def public_dict(self, *, include_content: bool = True) -> dict:
        result = {
            "path": self.path,
            "mode": self.mode,
            "build_order": self.order,
            "content_sha256": self.content_sha256,
            "size_bytes": self.size_bytes,
        }
        if include_content:
            result["content"] = self.content
        return result


@dataclass(frozen=True)
class LeanPackage:
    schema_version: int
    default_file: str
    files: tuple[LeanPackageFile, ...]
    verification: dict
    manifest: dict
    package_sha256: str

    @property
    def writable_paths(self) -> tuple[str, ...]:
        return tuple(item.path for item in self.files if item.mode == "writable")

    @property
    def readonly_paths(self) -> tuple[str, ...]:
        return tuple(item.path for item in self.files if item.mode == "readonly")

    @property
    def total_size(self) -> int:
        return sum(item.size_bytes for item in self.files)

    def public_dict(self, *, include_content: bool = True) -> dict:
        return {
            "schema_version": self.schema_version,
            "revision": self.package_sha256,
            "default_file": self.default_file,
            "verification": dict(self.verification),
            "files": [
                item.public_dict(include_content=include_content)
                for item in self.files
            ],
        }


def _normalize_relative_lean_path(raw_path: object) -> str:
    path = str(raw_path or "").strip()
    if not path or "\\" in path or "\x00" in path:
        raise LeanPackageError("Lean 文件路径无效")
    pure = PurePosixPath(path)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise LeanPackageError(f"Lean 文件路径不是规范相对路径：{path}")
    if pure.suffix != ".lean":
        raise LeanPackageError(f"Lean 题目包只能包含 .lean 源文件：{path}")
    stem_parts = list(pure.parts)
    stem_parts[-1] = stem_parts[-1][:-5]
    if any(not _PATH_PART_RE.fullmatch(part) for part in stem_parts):
        raise LeanPackageError(f"Lean 文件路径不能映射为模块名：{path}")
    normalized = pure.as_posix()
    if len(normalized.encode("ascii")) > 512:
        raise LeanPackageError(f"Lean 文件路径过长：{path}")
    return normalized


def _normalize_decl_name(value: object, field: str) -> str:
    name = str(value or "").strip()
    if not _DECLARATION_NAME_RE.fullmatch(name):
        raise LeanPackageError(f"verification.{field} 不是有效的 Lean 声明名")
    return name


def _module_for_declaration(declaration: str, modules: set[str], field: str) -> str:
    matches = [
        module
        for module in modules
        if declaration == module or declaration.startswith(module + ".")
    ]
    if not matches:
        raise LeanPackageError(f"verification.{field} 不属于题目包中的模块")
    return max(matches, key=len)


def _normalize_verification(raw: object, files: list[dict]) -> dict:
    if not isinstance(raw, dict):
        raise LeanPackageError("manifest.verification 必须是 JSON 对象")
    modules_by_path = {
        item["path"]: item["path"][:-5].replace("/", ".") for item in files
    }
    modules = set(modules_by_path.values())

    target_decl = _normalize_decl_name(
        raw.get("target_decl") or raw.get("target"), "target_decl"
    )
    entry_decl = _normalize_decl_name(
        raw.get("entry_decl") or raw.get("entry"), "entry_decl"
    )
    target_module = str(raw.get("target_module") or "").strip()
    entry_module = str(raw.get("entry_module") or "").strip()
    if target_module:
        target_module = _normalize_decl_name(target_module, "target_module")
    else:
        target_module = _module_for_declaration(
            target_decl, modules, "target_decl"
        )
    if entry_module:
        entry_module = _normalize_decl_name(entry_module, "entry_module")
    else:
        entry_module = _module_for_declaration(entry_decl, modules, "entry_decl")

    if target_module not in modules:
        raise LeanPackageError("verification.target_module 不在题目包中")
    if entry_module not in modules:
        raise LeanPackageError("verification.entry_module 不在题目包中")
    mode_by_module = {
        modules_by_path[item["path"]]: item["mode"] for item in files
    }
    if mode_by_module[target_module] != "readonly":
        raise LeanPackageError("目标声明必须位于只读文件中")
    if mode_by_module[entry_module] != "writable":
        raise LeanPackageError("学生证明入口必须位于可写文件中")

    permitted = raw.get("permitted_axioms")
    if permitted is None:
        permitted = list(DEFAULT_PERMITTED_AXIOMS)
    if not isinstance(permitted, list):
        raise LeanPackageError("verification.permitted_axioms 必须是声明名数组")
    normalized_axioms = []
    for value in permitted:
        name = _normalize_decl_name(value, "permitted_axioms")
        if name not in normalized_axioms:
            normalized_axioms.append(name)

    return {
        "target_module": target_module,
        "target_decl": target_decl,
        "entry_module": entry_module,
        "entry_decl": entry_decl,
        "permitted_axioms": normalized_axioms,
    }


def build_lean_package(manifest: object, contents: dict[str, str]) -> LeanPackage:
    """由已读取的 manifest 与 UTF-8 源文件构造规范题目包。"""

    if not isinstance(manifest, dict):
        raise LeanPackageError("numoj-lean.json 必须是 JSON 对象")
    try:
        schema_version = int(manifest.get("schema_version"))
    except (TypeError, ValueError) as exc:
        raise LeanPackageError("manifest.schema_version 无效") from exc
    if schema_version != LEAN_PACKAGE_SCHEMA_VERSION:
        raise LeanPackageError(
            f"仅支持 Lean 题目包 schema_version={LEAN_PACKAGE_SCHEMA_VERSION}"
        )

    raw_files = manifest.get("files")
    if not isinstance(raw_files, list) or not raw_files:
        raise LeanPackageError("manifest.files 必须是非空数组")
    if len(raw_files) > MAX_LEAN_FILES:
        raise LeanPackageError(f"Lean 题目包最多包含 {MAX_LEAN_FILES} 个文件")

    descriptors: list[dict] = []
    seen_paths: set[str] = set()
    for raw in raw_files:
        if not isinstance(raw, dict):
            raise LeanPackageError("manifest.files 中的项目必须是 JSON 对象")
        path = _normalize_relative_lean_path(raw.get("path"))
        mode = str(raw.get("mode") or "").strip().lower()
        if mode not in {"readonly", "writable"}:
            raise LeanPackageError(f"文件 {path} 的 mode 必须是 readonly 或 writable")
        if path in seen_paths:
            raise LeanPackageError(f"manifest.files 中存在重复路径：{path}")
        if mode == "writable" and path.split("/", 1)[0].removesuffix(".lean") in _RESERVED_WRITABLE_ROOTS:
            raise LeanPackageError(f"可写文件不能占用 Lean 保留模块：{path}")
        seen_paths.add(path)
        descriptors.append({"path": path, "mode": mode})

    if not any(item["mode"] == "readonly" for item in descriptors):
        raise LeanPackageError("Lean 题目包至少需要一个只读文件")
    if not any(item["mode"] == "writable" for item in descriptors):
        raise LeanPackageError("Lean 题目包至少需要一个可写文件")

    default_file = _normalize_relative_lean_path(manifest.get("default_file"))
    descriptor_by_path = {item["path"]: item for item in descriptors}
    if default_file not in descriptor_by_path:
        raise LeanPackageError("manifest.default_file 不在 files 中")
    if descriptor_by_path[default_file]["mode"] != "writable":
        raise LeanPackageError("manifest.default_file 必须可写")

    raw_order = manifest.get("build_order")
    if not isinstance(raw_order, list):
        raise LeanPackageError("manifest.build_order 必须是文件路径数组")
    build_order = [_normalize_relative_lean_path(path) for path in raw_order]
    if len(build_order) != len(set(build_order)) or set(build_order) != seen_paths:
        raise LeanPackageError("manifest.build_order 必须恰好包含 files 中的全部路径")
    saw_writable = False
    for path in build_order:
        mode = descriptor_by_path[path]["mode"]
        if mode == "writable":
            saw_writable = True
        elif saw_writable:
            raise LeanPackageError("只读文件必须排在所有可写文件之前构建")

    content_paths = set(contents)
    if content_paths != seen_paths:
        missing = sorted(seen_paths.difference(content_paths))
        extra = sorted(content_paths.difference(seen_paths))
        details = []
        if missing:
            details.append("缺少 " + ", ".join(missing))
        if extra:
            details.append("未声明 " + ", ".join(extra))
        raise LeanPackageError("题目包文件与 manifest 不一致：" + "；".join(details))

    order_by_path = {path: index for index, path in enumerate(build_order)}
    package_files = []
    total_size = 0
    for descriptor in descriptors:
        path = descriptor["path"]
        content = contents[path]
        if not isinstance(content, str):
            raise LeanPackageError(f"文件不是 UTF-8 文本：{path}")
        encoded = content.encode("utf-8")
        if len(encoded) > MAX_LEAN_FILE_BYTES:
            raise LeanPackageError(f"Lean 文件超过 1 MiB：{path}")
        total_size += len(encoded)
        if total_size > MAX_LEAN_TOTAL_BYTES:
            raise LeanPackageError("Lean 题目包源码总大小超过 8 MiB")
        package_files.append(
            LeanPackageFile(
                path=path,
                mode=descriptor["mode"],
                order=order_by_path[path],
                content=content,
                content_sha256=hashlib.sha256(encoded).hexdigest(),
                size_bytes=len(encoded),
            )
        )
    package_files.sort(key=lambda item: item.order)

    verification = _normalize_verification(
        manifest.get("verification"), descriptors
    )
    canonical_manifest = {
        "schema_version": schema_version,
        "default_file": default_file,
        "files": [
            {"path": item.path, "mode": item.mode} for item in package_files
        ],
        "build_order": [item.path for item in package_files],
        "verification": verification,
    }
    digest_payload = {
        "manifest": canonical_manifest,
        "files": [
            {
                "path": item.path,
                "content_sha256": item.content_sha256,
                "size_bytes": item.size_bytes,
            }
            for item in package_files
        ],
    }
    package_sha256 = hashlib.sha256(
        json.dumps(
            digest_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return LeanPackage(
        schema_version=schema_version,
        default_file=default_file,
        files=tuple(package_files),
        verification=verification,
        manifest=canonical_manifest,
        package_sha256=package_sha256,
    )


def load_lean_package_directory(directory: str | os.PathLike[str]) -> LeanPackage:
    root = Path(directory)
    manifest_path = root / MANIFEST_FILENAME
    if not manifest_path.is_file():
        raise LeanPackageError(f"ZIP 根目录缺少 {MANIFEST_FILENAME}")
    if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
        raise LeanPackageError("Lean manifest 超过 128 KiB")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except UnicodeDecodeError as exc:
        raise LeanPackageError("numoj-lean.json 不是 UTF-8 文本") from exc
    except json.JSONDecodeError as exc:
        raise LeanPackageError("numoj-lean.json 不是有效 JSON") from exc

    raw_files = manifest.get("files") if isinstance(manifest, dict) else None
    declared_paths = []
    if isinstance(raw_files, list):
        for item in raw_files:
            if isinstance(item, dict):
                declared_paths.append(_normalize_relative_lean_path(item.get("path")))

    actual_files = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path != manifest_path
    }
    if any(path.endswith("/") for path in actual_files):
        raise LeanPackageError("Lean 题目包包含无效文件路径")
    contents = {}
    for relative_path in declared_paths:
        source_path = root.joinpath(*PurePosixPath(relative_path).parts)
        if not source_path.is_file():
            continue
        try:
            contents[relative_path] = source_path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise LeanPackageError(f"Lean 文件不是 UTF-8 文本：{relative_path}") from exc
    if actual_files != set(declared_paths):
        missing = sorted(set(declared_paths).difference(actual_files))
        extra = sorted(actual_files.difference(declared_paths))
        details = []
        if missing:
            details.append("缺少 " + ", ".join(missing))
        if extra:
            details.append("未声明 " + ", ".join(extra))
        raise LeanPackageError("ZIP 中的文件与 manifest 不一致：" + "；".join(details))
    return build_lean_package(manifest, contents)


def load_lean_package_zip(
    zip_path: str | os.PathLike[str],
    extract_directory: str | os.PathLike[str],
) -> LeanPackage:
    """安全解压 ZIP 后读取一个 Lean 题目包。"""

    try:
        extract_zip(
            zip_path,
            extract_directory,
            policy=ZipExtractionPolicy(
                max_members=MAX_LEAN_FILES + 32,
                max_file_bytes=max(MAX_LEAN_FILE_BYTES, MAX_MANIFEST_BYTES),
                max_total_bytes=MAX_LEAN_TOTAL_BYTES + MAX_MANIFEST_BYTES,
                max_compression_ratio=200,
                require_non_empty=True,
                cleanup_on_error=True,
            ),
        )
    except ArchiveExtractionError as exc:
        raise LeanPackageError("Lean 题目包不符合 ZIP 安全限制") from exc
    return load_lean_package_directory(extract_directory)


__all__ = [
    "DEFAULT_PERMITTED_AXIOMS",
    "LEAN_PACKAGE_SCHEMA_VERSION",
    "LeanPackage",
    "LeanPackageError",
    "LeanPackageFile",
    "MANIFEST_FILENAME",
    "build_lean_package",
    "load_lean_package_directory",
    "load_lean_package_zip",
]
