"""Managed C/C++ header toolchain shared by clangd and production deploys.

The judge image, rather than the web host, defines which third-party headers
users may include.  Deploys export those headers into an inactive managed slot
and publish a small manifest.  clangd reads only the currently selected slot.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Any

from oj_modules.project_paths import PROJECT_ROOT


EDITOR_TOOLCHAIN_SCHEMA_VERSION = 1
EDITOR_TOOLCHAIN_ENV = "NUMOJ_EDITOR_TOOLCHAIN_ROOT"
DEFAULT_CURRENT_TOOLCHAIN = PROJECT_ROOT / ".deploy" / "current-editor-toolchain"
MANIFEST_FILENAME = "manifest.json"
COMPILER_SEARCH_FILENAME = "compiler-search.json"
_MAX_INCLUDE_PATHS = 64


class EditorToolchainError(RuntimeError):
    """A managed toolchain is missing, malformed, or escaped its root."""


@dataclass(frozen=True)
class EditorToolchain:
    """Validated clangd-facing view of one exported judge toolchain."""

    root: Path
    c_include_paths: tuple[Path, ...]
    cpp_include_paths: tuple[Path, ...]
    required_headers: tuple[Path, ...]
    source_image_reference: str
    source_image_id: str

    @property
    def include_paths(self) -> tuple[Path, ...]:
        """Backward-compatible C++ view for diagnostics and older callers."""

        return self.cpp_include_paths

    def include_paths_for(self, language: str) -> tuple[Path, ...]:
        if language == "c":
            return self.c_include_paths
        if language == "cpp":
            return self.cpp_include_paths
        raise ValueError(f"不支持的 C/C++ 工具链语言：{language}")


def _safe_relative_path(raw_value: Any, *, label: str) -> PurePosixPath:
    if not isinstance(raw_value, str) or not raw_value:
        raise EditorToolchainError(f"{label} 必须是非空相对路径")
    if "\\" in raw_value:
        raise EditorToolchainError(f"{label} 不能包含反斜杠")
    relative = PurePosixPath(raw_value)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise EditorToolchainError(f"{label} 超出受管工具链")
    return relative


def _resolve_member(
    root: Path,
    raw_value: Any,
    *,
    label: str,
    expect_directory: bool,
) -> Path:
    relative = _safe_relative_path(raw_value, label=label)
    candidate = root.joinpath(*relative.parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        raise EditorToolchainError(f"{label} 不存在或超出受管工具链") from exc
    if expect_directory:
        if not resolved.is_dir():
            raise EditorToolchainError(f"{label} 不是目录")
    elif not resolved.is_file():
        raise EditorToolchainError(f"{label} 不是普通文件")
    return resolved


def _load_manifest(root: Path) -> dict[str, Any]:
    manifest_path = root / MANIFEST_FILENAME
    try:
        mode = manifest_path.lstat().st_mode
    except FileNotFoundError as exc:
        raise EditorToolchainError("受管工具链缺少 manifest.json") from exc
    if not stat.S_ISREG(mode):
        raise EditorToolchainError("受管工具链 manifest.json 必须是普通文件")
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EditorToolchainError("受管工具链 manifest.json 无效") from exc
    if not isinstance(payload, dict):
        raise EditorToolchainError("受管工具链 manifest.json 顶层必须是对象")
    return payload


def load_editor_toolchain(
    root: Path | str | None = None,
    *,
    required: bool = False,
) -> EditorToolchain | None:
    """Load and validate the selected judge-image header export.

    An explicit argument or environment override is fail-closed.  The default
    link may be absent in local development, but a broken or malformed managed
    link is never silently replaced with host headers.
    """

    explicit_root = root is not None
    if root is None:
        environment_root = os.environ.get(EDITOR_TOOLCHAIN_ENV, "").strip()
        if environment_root:
            root = environment_root
            explicit_root = True
        else:
            root = DEFAULT_CURRENT_TOOLCHAIN

    selected = Path(root)
    if not selected.exists():
        if selected.is_symlink() or explicit_root or required:
            raise EditorToolchainError(
                f"受管编辑器工具链不存在：{selected}"
            )
        return None
    if not explicit_root and not selected.is_symlink():
        raise EditorToolchainError(
            f"{DEFAULT_CURRENT_TOOLCHAIN} 必须是部署脚本管理的符号链接"
        )
    try:
        resolved_root = selected.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise EditorToolchainError("无法解析受管编辑器工具链") from exc
    if not resolved_root.is_dir():
        raise EditorToolchainError("受管编辑器工具链根不是目录")

    manifest = _load_manifest(resolved_root)
    if manifest.get("schema_version") != EDITOR_TOOLCHAIN_SCHEMA_VERSION:
        raise EditorToolchainError("受管编辑器工具链 manifest 版本不受支持")

    raw_c_include_paths = manifest.get("c_include_paths")
    raw_cpp_include_paths = manifest.get("cpp_include_paths")
    raw_required_headers = manifest.get("required_headers")
    for label, raw_include_paths in (
        ("c_include_paths", raw_c_include_paths),
        ("cpp_include_paths", raw_cpp_include_paths),
    ):
        if (
            not isinstance(raw_include_paths, list)
            or not raw_include_paths
            or len(raw_include_paths) > _MAX_INCLUDE_PATHS
        ):
            raise EditorToolchainError(
                f"受管编辑器工具链 {label} 无效"
            )
    if (
        not isinstance(raw_required_headers, list)
        or not raw_required_headers
        or len(raw_required_headers) > _MAX_INCLUDE_PATHS
    ):
        raise EditorToolchainError("受管编辑器工具链 required_headers 无效")

    c_include_paths = tuple(
        _resolve_member(
            resolved_root,
            raw_path,
            label=f"c_include_paths[{index}]",
            expect_directory=True,
        )
        for index, raw_path in enumerate(raw_c_include_paths)
    )
    cpp_include_paths = tuple(
        _resolve_member(
            resolved_root,
            raw_path,
            label=f"cpp_include_paths[{index}]",
            expect_directory=True,
        )
        for index, raw_path in enumerate(raw_cpp_include_paths)
    )
    required_headers = tuple(
        _resolve_member(
            resolved_root,
            raw_path,
            label=f"required_headers[{index}]",
            expect_directory=False,
        )
        for index, raw_path in enumerate(raw_required_headers)
    )

    source_reference = manifest.get("source_image_reference")
    source_image_id = manifest.get("source_image_id")
    if not isinstance(source_reference, str) or not source_reference:
        raise EditorToolchainError("受管编辑器工具链缺少来源镜像引用")
    if (
        not isinstance(source_image_id, str)
        or not source_image_id.startswith("sha256:")
        or len(source_image_id) <= len("sha256:")
    ):
        raise EditorToolchainError("受管编辑器工具链缺少来源镜像 ID")

    return EditorToolchain(
        root=resolved_root,
        c_include_paths=c_include_paths,
        cpp_include_paths=cpp_include_paths,
        required_headers=required_headers,
        source_image_reference=source_reference,
        source_image_id=source_image_id,
    )


def _relative_to_root(root: Path, path: Path) -> str:
    return path.resolve(strict=True).relative_to(root).as_posix()


def build_editor_toolchain_manifest(
    root: Path,
    *,
    source_image_reference: str,
    source_image_id: str,
) -> dict[str, Any]:
    """Discover exported include roots and representative required headers."""

    resolved_root = root.resolve(strict=True)
    usr_include = resolved_root / "usr" / "include"
    mkl_include = resolved_root / "opt" / "mkl" / "include"
    shared_include = resolved_root / "opt" / "library"
    compiler_search_path = resolved_root / COMPILER_SEARCH_FILENAME
    try:
        compiler_search_mode = compiler_search_path.lstat().st_mode
        if not stat.S_ISREG(compiler_search_mode):
            raise EditorToolchainError(
                "判题镜像 compiler-search.json 必须是普通文件"
            )
        compiler_search = json.loads(
            compiler_search_path.read_text(encoding="utf-8")
        )
    except (
        FileNotFoundError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
    ) as exc:
        raise EditorToolchainError(
            "判题镜像缺少有效的 compiler-search.json"
        ) from exc
    if (
        not isinstance(compiler_search, dict)
        or compiler_search.get("schema_version") != 1
    ):
        raise EditorToolchainError("判题镜像 compiler-search.json 版本无效")

    def mapped_compiler_paths(language: str) -> tuple[Path, ...]:
        raw_paths = compiler_search.get(language)
        if (
            not isinstance(raw_paths, list)
            or not raw_paths
            or len(raw_paths) > _MAX_INCLUDE_PATHS
        ):
            raise EditorToolchainError(
                f"判题镜像 {language} include search 无效"
            )
        mapped: list[Path] = []
        for index, raw_path in enumerate(raw_paths):
            if (
                not isinstance(raw_path, str)
                or not raw_path.startswith("/")
                or "\\" in raw_path
            ):
                raise EditorToolchainError(
                    f"判题镜像 {language} include search 路径无效"
                )
            relative = _safe_relative_path(
                raw_path.lstrip("/"),
                label=f"{language}[{index}]",
            )
            candidate = resolved_root.joinpath(*relative.parts)
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(resolved_root)
            except (FileNotFoundError, RuntimeError, ValueError) as exc:
                raise EditorToolchainError(
                    f"判题镜像 {language} include search 未完整导出"
                ) from exc
            if not resolved.is_dir():
                raise EditorToolchainError(
                    f"判题镜像 {language} include search 不是目录"
                )
            if resolved not in mapped:
                mapped.append(resolved)
        return tuple(mapped)

    compiler_c_paths = mapped_compiler_paths("c")
    compiler_cpp_paths = mapped_compiler_paths("cpp")

    cpp_vectors = sorted(
        path
        for path in usr_include.glob("c++/*/vector")
        if path.is_file()
    )
    eigen_header = usr_include / "eigen3" / "Eigen" / "Eigen"
    eigen_sparse_lu = usr_include / "eigen3" / "Eigen" / "SparseLU"
    cblas_headers = sorted(
        path for path in usr_include.rglob("cblas.h") if path.is_file()
    )
    lapacke_headers = sorted(
        path for path in usr_include.rglob("lapacke.h") if path.is_file()
    )
    mkl_header = mkl_include / "mkl.h"

    required_groups = (
        ("C++ 标准库", cpp_vectors),
        ("Eigen", [eigen_header] if eigen_header.is_file() else []),
        (
            "Eigen::SparseLU",
            [eigen_sparse_lu] if eigen_sparse_lu.is_file() else [],
        ),
        ("CBLAS", cblas_headers),
        ("LAPACKE", lapacke_headers),
        ("MKL", [mkl_header] if mkl_header.is_file() else []),
    )
    missing = [label for label, candidates in required_groups if not candidates]
    if missing:
        raise EditorToolchainError(
            "判题镜像缺少官方 C/C++ 头文件：" + "、".join(missing)
        )

    def combined_include_paths(
        explicit_paths: tuple[Path, ...],
        compiler_paths: tuple[Path, ...],
    ) -> list[Path]:
        include_paths: list[Path] = []
        for path in (*explicit_paths, *compiler_paths):
            if not path.is_dir():
                continue
            resolved = path.resolve(strict=True)
            try:
                resolved.relative_to(resolved_root)
            except ValueError as exc:
                raise EditorToolchainError(
                    "导出的 include 路径逃逸"
                ) from exc
            if resolved not in include_paths:
                include_paths.append(resolved)
        return include_paths

    def require_directory(path: Path, label: str) -> Path:
        if path.is_dir():
            return path
        raise EditorToolchainError(
            f"判题镜像缺少官方 include 目录：{label}"
        )

    c_include_paths = combined_include_paths(
        (
            require_directory(shared_include, "/opt/library"),
            require_directory(mkl_include, "/opt/mkl/include"),
        ),
        compiler_c_paths,
    )
    cpp_include_paths = combined_include_paths(
        (
            require_directory(shared_include, "/opt/library"),
            require_directory(usr_include / "eigen3", "Eigen"),
            require_directory(mkl_include, "/opt/mkl/include"),
        ),
        compiler_cpp_paths,
    )

    required_headers = [
        candidates[0] for _, candidates in required_groups
    ]
    return {
        "schema_version": EDITOR_TOOLCHAIN_SCHEMA_VERSION,
        "source_image_reference": source_image_reference,
        "source_image_id": source_image_id,
        "c_include_paths": [
            _relative_to_root(resolved_root, path)
            for path in c_include_paths
        ],
        "cpp_include_paths": [
            _relative_to_root(resolved_root, path)
            for path in cpp_include_paths
        ],
        "required_headers": [
            _relative_to_root(resolved_root, path)
            for path in required_headers
        ],
    }
