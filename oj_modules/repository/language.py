"""代码仓库语言服务所需的、带代次校验的只读快照。"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import PurePosixPath

from oj_modules.infrastructure.mysql import get_db_connection
from oj_modules.repository import storage
from oj_modules.repository import tree


_C_SUFFIXES = frozenset({".c"})
_CPP_SUFFIXES = frozenset({".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"})
_PYTHON_SUFFIXES = frozenset({".py"})
_MATLAB_SUFFIXES = frozenset({".m"})


@dataclass(frozen=True)
class RepositorySemanticTarget:
    owner_id: int
    storage_key: str
    generation: int
    entry_id: int
    relative_path: str
    language: str


@dataclass(frozen=True)
class RepositorySemanticFile:
    relative_path: str
    content: bytes


@dataclass(frozen=True)
class RepositorySemanticSnapshot:
    target: RepositorySemanticTarget
    directories: tuple[str, ...]
    files: tuple[RepositorySemanticFile, ...]
    total_size: int


def _expected_suffixes(language: str) -> frozenset[str]:
    normalized = str(language or "").lower()
    if normalized == "c":
        return _C_SUFFIXES
    if normalized == "cpp":
        return _CPP_SUFFIXES
    if normalized in {"py", "python"}:
        return _PYTHON_SUFFIXES
    if normalized in {"matlab", "octave"}:
        return _MATLAB_SUFFIXES
    raise tree.RepositoryDomainError(
        "该语言暂不支持结构化高亮",
        code="unsupported_language",
        status=400,
    )


def _validate_target_row(
    owner_id: int,
    storage_key: str,
    generation: int,
    entry_id: int,
    language: str,
    row,
) -> RepositorySemanticTarget:
    if not row or row["entry_type"] != "file":
        raise tree.RepositoryDomainError(
            "仓库文件不存在",
            code="not_found",
            status=404,
        )
    relative_path = storage.validate_relative_path(row["relative_path"])
    suffix = PurePosixPath(relative_path).suffix.lower()
    if suffix not in _expected_suffixes(language):
        raise tree.RepositoryDomainError(
            "仓库文件类型与语言不匹配",
            code="language_mismatch",
            status=400,
        )
    return RepositorySemanticTarget(
        owner_id=int(owner_id),
        storage_key=storage.validate_storage_key(storage_key),
        generation=int(generation),
        entry_id=int(entry_id),
        relative_path=relative_path,
        language="python" if language == "py" else str(language).lower(),
    )


def get_repository_semantic_target(
    owner_id: int,
    entry_id: int,
    language: str,
) -> RepositorySemanticTarget:
    """只读取当前代次与目标路径；路径永远由服务端元数据推导。"""

    owner_id = int(owner_id)
    entry_id = int(entry_id)
    with tree.repository_user_lock(
        owner_id,
        exclusive=False,
    ) as locked_state:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                state = tree._load_state(cursor, owner_id)
                row = tree._find_entry(cursor, owner_id, entry_id=entry_id)
        finally:
            conn.close()
    return _validate_target_row(
        owner_id,
        locked_state["storage_key"],
        int(state["repository_generation"]),
        entry_id,
        language,
        row,
    )


def capture_repository_semantic_snapshot(
    expected_target: RepositorySemanticTarget,
) -> RepositorySemanticSnapshot:
    """在一次共享锁内读取完整目录树，并拒绝任何代次或内容漂移。"""

    owner_id = int(expected_target.owner_id)
    with tree.repository_user_lock(owner_id, exclusive=False) as locked_state:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                state = tree._load_state(cursor, owner_id)
                rows = tree._load_entries(cursor, owner_id)
        finally:
            conn.close()

        generation = int(state["repository_generation"])
        if (
            generation != int(expected_target.generation)
            or locked_state["storage_key"] != expected_target.storage_key
        ):
            raise tree.RepositoryDomainError(
                "仓库内容已变化，请重试实时解析",
                code="repository_changed",
                status=409,
            )
        target_row = next(
            (row for row in rows if int(row["id"]) == expected_target.entry_id),
            None,
        )
        target = _validate_target_row(
            owner_id,
            locked_state["storage_key"],
            generation,
            expected_target.entry_id,
            expected_target.language,
            target_row,
        )
        if target.relative_path != expected_target.relative_path:
            raise tree.RepositoryDomainError(
                "仓库文件路径已变化，请重试实时解析",
                code="repository_changed",
                status=409,
            )

        directories: list[str] = []
        files: list[RepositorySemanticFile] = []
        total_size = 0
        for row in rows:
            relative_path = storage.validate_relative_path(row["relative_path"])
            if row["entry_type"] == "directory":
                directories.append(relative_path)
                continue
            if row["entry_type"] != "file":
                raise tree.RepositoryDomainError(
                    "仓库条目类型非法",
                    code="tree_corrupt",
                    status=500,
                )
            raw = storage.read_file(locked_state["storage_key"], relative_path)
            total_size += len(raw)
            if (
                len(raw) != int(row["file_size"])
                or hashlib.sha256(raw).hexdigest() != row["content_sha256"]
            ):
                raise tree.RepositoryDomainError(
                    f"仓库文件校验失败：{relative_path}",
                    code="content_integrity_error",
                    status=500,
                )
            if total_size > storage.MAX_TOTAL_BYTES:
                raise tree.RepositoryDomainError(
                    "代码仓库超过实时解析总量限制",
                    code="repository_too_large",
                    status=413,
                )
            files.append(
                RepositorySemanticFile(
                    relative_path=relative_path,
                    content=raw,
                )
            )

    return RepositorySemanticSnapshot(
        target=target,
        directories=tuple(directories),
        files=tuple(files),
        total_size=total_size,
    )


def ensure_repository_semantic_target_current(
    expected_target: RepositorySemanticTarget,
) -> None:
    """在返回语义结果前建立一次当前代次的线性化检查点。"""

    try:
        current_target = get_repository_semantic_target(
            expected_target.owner_id,
            expected_target.entry_id,
            expected_target.language,
        )
    except tree.RepositoryDomainError as exc:
        raise tree.RepositoryDomainError(
            "仓库内容已变化，请重试实时解析",
            code="repository_changed",
            status=409,
        ) from exc
    if current_target != expected_target:
        raise tree.RepositoryDomainError(
            "仓库内容已变化，请重试实时解析",
            code="repository_changed",
            status=409,
        )
