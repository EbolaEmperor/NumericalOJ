#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""人工书面作业覆盖的可恢复文件发布边界。

数据库永远最后切换到已经完整落盘的不可变上传文件。文件阶段使用持久 journal；若
Web worker 被 SIGKILL、宿主断电，恢复器可根据数据库当前指向的 generation 决定完成
清理或回滚，而不是依赖进程内 ``except`` 补偿。归档仍是派生产物，但也随 journal
恢复到与数据库一致的版本。
"""

from __future__ import annotations

import fcntl
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import shutil
import time
from uuid import uuid4

from backend.oj_modules.submissions import archive as submission_archive
from backend.oj_modules.observability import emit_audit


logger = logging.getLogger(__name__)

JOURNAL_DIRNAME = ".written-publications"
STAGING_DIRNAME = ".written-staging"
READY_MARKER = ".publication-ready"
JOURNAL_VERSION = 1
DEFAULT_RECOVERY_GRACE_SECONDS = 15 * 60
_TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class WrittenSubmissionArtifactError(RuntimeError):
    """新作业未能发布；异常消息会说明旧版本是否已确定保留。"""

    def __init__(self, message, *, compensation_errors=()):
        self.compensation_errors = tuple(compensation_errors)
        super().__init__(message)


class WrittenSubmissionPublicationConflict(RuntimeError):
    """数据库已被另一流程推进，自动恢复不能安全猜测。"""


def _path_exists(path):
    path = Path(path)
    return path.exists() or path.is_symlink()


def _remove_path(path):
    path = Path(path)
    if not _path_exists(path):
        return
    if path.is_symlink() or path.is_file():
        path.unlink()
    else:
        shutil.rmtree(path)


def _fsync_directory(path):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write_json(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{uuid4().hex}")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if _path_exists(temporary):
            temporary.unlink()


def _write_ready_marker(directory, token):
    marker = Path(directory) / READY_MARKER
    with marker.open("x", encoding="ascii") as stream:
        stream.write(f"{token}\n")
        stream.flush()
        os.fsync(stream.fileno())
    _fsync_directory(marker.parent)


def _has_ready_marker(directory, token):
    marker = Path(directory) / READY_MARKER
    try:
        return marker.is_file() and marker.read_text(encoding="ascii").strip() == token
    except OSError:
        return False


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _active_filename(submission):
    value = (submission or {}).get("test_points")
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    elif isinstance(value, str):
        text = value.strip()
        if text:
            try:
                decoded = json.loads(text.splitlines()[0])
                value = decoded[0] if isinstance(decoded, list) and decoded else decoded
            except (TypeError, ValueError, json.JSONDecodeError):
                value = text
    if value is None:
        return None
    name = os.path.basename(str(value).strip())
    return name or None


def _stored_filename(filename, token):
    path = Path(filename)
    suffix = path.suffix.lower()
    stem = path.stem[: max(1, 230 - len(suffix))]
    return f"{stem}.{token[:12]}{suffix}"


def _validate_staged_file(path, *, filename, allowed_extensions, max_bytes):
    if Path(filename).name != filename or filename in {"", ".", ".."}:
        raise ValueError("上传文件名不合法")

    suffix = Path(filename).suffix.lower()
    normalized_extensions = {
        str(extension).lower()
        if str(extension).startswith(".")
        else f".{str(extension).lower()}"
        for extension in allowed_extensions
    }
    if suffix not in normalized_extensions:
        raise ValueError("上传文件格式不受支持")

    size = path.stat().st_size
    if size <= 0:
        raise ValueError("上传文件不能为空")
    if size > int(max_bytes):
        raise ValueError(f"上传文件超过大小限制（{int(max_bytes)} 字节）")


def _build_archive_staging(
    archive_staging,
    *,
    staged_file,
    filename,
    previous_submission,
    problem,
    user,
    classes,
):
    proposed_submission = dict(previous_submission)
    proposed_submission.update({
        "created_at": datetime.now(),
        "score": 0,
        "status": "Pending",
        "test_points": [filename],
    })
    submission_archive.archive_submission_record(
        proposed_submission,
        problem,
        user,
        classes,
        archive_dir=archive_staging,
    )
    archived_file = submission_archive.archive_uploaded_submission_file(
        proposed_submission["id"],
        staged_file,
        filename,
        archive_dir=archive_staging,
    )
    if not archived_file:
        raise RuntimeError("新作业文件未能写入归档 staging")


class _DirectorySwap:
    """可从持久 journal 重放的目录切换。"""

    def __init__(self, staging, target, *, token):
        self.staging = Path(staging)
        self.target = Path(target)
        self.token = token
        self.backup = self.target.with_name(
            f".{self.target.name}.backup-{token}"
        )

    def publish(self):
        self.target.parent.mkdir(parents=True, exist_ok=True)
        if _has_ready_marker(self.target, self.token):
            return
        if not _has_ready_marker(self.staging, self.token):
            raise RuntimeError("归档 staging 未完整落盘")
        if _path_exists(self.backup):
            if _path_exists(self.target):
                raise WrittenSubmissionPublicationConflict("归档目标与备份同时存在且目标不是新版本")
        elif _path_exists(self.target):
            os.replace(self.target, self.backup)
            _fsync_directory(self.target.parent)
        os.replace(self.staging, self.target)
        _fsync_directory(self.target.parent)

    def rollback(self):
        if _has_ready_marker(self.target, self.token):
            _remove_path(self.target)
        elif _path_exists(self.target) and _path_exists(self.backup):
            raise WrittenSubmissionPublicationConflict("归档目标已被其他流程改写")
        if _path_exists(self.backup):
            os.replace(self.backup, self.target)
            _fsync_directory(self.target.parent)
        _remove_path(self.staging)

    def finalize(self):
        marker = self.target / READY_MARKER
        if _has_ready_marker(self.target, self.token):
            marker.unlink()
            _fsync_directory(self.target)
        _remove_path(self.backup)
        _remove_path(self.staging)


def _publication_paths(upload_root, submission_id, token, stored_filename):
    upload_root = Path(upload_root)
    key = f"{int(submission_id)}-{token}"
    archive_target = Path(submission_archive.archive_dir_for_submission(submission_id))
    upload_staging = upload_root / STAGING_DIRNAME / key
    return {
        "journal": upload_root / JOURNAL_DIRNAME / f"{key}.json",
        "lock": upload_root / ".locks" / f"{int(submission_id)}.lock",
        "upload_staging": upload_staging,
        "staged_file": upload_staging / stored_filename,
        "upload_target": upload_root / str(int(submission_id)),
        "upload_destination": upload_root / str(int(submission_id)) / stored_filename,
        "archive_target": archive_target,
        "archive_staging": archive_target.with_name(
            f".{archive_target.name}.staging-{token}"
        ),
    }


def _validated_journal(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    token = str(data.get("token") or "")
    digest = str(data.get("sha256") or "")
    submission_id = int(data.get("submission_id") or 0)
    stored_filename = str(data.get("stored_filename") or "")
    if (
        data.get("version") != JOURNAL_VERSION
        or not _TOKEN_RE.fullmatch(token)
        or not _SHA256_RE.fullmatch(digest)
        or submission_id <= 0
        or Path(stored_filename).name != stored_filename
        or not stored_filename
        or data.get("state") not in {"prepared", "db_committed"}
        or Path(path).name != f"{submission_id}-{token}.json"
    ):
        raise ValueError(f"非法书面作业 publication journal: {path}")
    return data


def _install_upload(paths, expected_sha256):
    destination = paths["upload_destination"]
    staged_file = paths["staged_file"]
    paths["upload_target"].mkdir(parents=True, exist_ok=True)
    if _path_exists(destination):
        if destination.is_file() and _sha256(destination) == expected_sha256:
            return
        raise WrittenSubmissionPublicationConflict("generation 上传文件已存在但内容不同")
    os.link(staged_file, destination)
    _fsync_directory(destination.parent)


def _remove_generation_upload(paths, expected_sha256):
    destination = paths["upload_destination"]
    if not _path_exists(destination):
        return
    if not destination.is_file() or _sha256(destination) != expected_sha256:
        raise WrittenSubmissionPublicationConflict("generation 上传文件已被其他流程改写")
    destination.unlink()
    _fsync_directory(destination.parent)


def _cleanup_published(paths, journal, archive_swap):
    errors = []
    try:
        archive_swap.finalize()
    except Exception as exc:  # pragma: no cover - 二次磁盘故障
        errors.append(exc)
        logger.exception("人工作业归档旧版本清理失败")
    try:
        destination = paths["upload_destination"]
        for child in paths["upload_target"].iterdir():
            if child != destination:
                _remove_path(child)
        _remove_path(paths["upload_staging"])
    except Exception as exc:  # pragma: no cover - 二次磁盘故障
        errors.append(exc)
        logger.exception("人工作业上传旧版本清理失败")
    if not errors:
        try:
            Path(journal).unlink(missing_ok=True)
            _fsync_directory(Path(journal).parent)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)
            logger.exception("人工作业 publication journal 清理失败")
    return errors


def _rollback_prepared(paths, data, archive_swap):
    errors = []
    try:
        archive_swap.rollback()
    except Exception as exc:
        errors.append(exc)
    try:
        _remove_generation_upload(paths, data["sha256"])
        _remove_path(paths["upload_staging"])
    except Exception as exc:
        errors.append(exc)
    if not errors:
        paths["journal"].unlink(missing_ok=True)
        _fsync_directory(paths["journal"].parent)
    return errors


def _audit_published_submission(*, submission_id, token, data, destination, problem, user):
    try:
        size = Path(destination).stat().st_size
    except OSError:
        size = None
    emit_audit(
        "submissions",
        action="submission.artifact.published",
        outcome="success",
        message="人工书面提交文件已发布",
        submission={
            "id": submission_id,
            "kind": "written",
            "origin": "manual_overwrite",
            "publication_id": token,
        },
        problem={"id": (problem or {}).get("id")},
        user={
            "id": (user or {}).get("id"),
            "name": (user or {}).get("username"),
        },
        artifact={
            "type": "written",
            "bytes": size,
            "sha256": data.get("sha256"),
        },
    )


def publish_manual_written_submission(
    *,
    uploaded_file,
    filename,
    previous_submission,
    problem,
    user,
    classes,
    overwrite_record,
    load_current_record,
    max_bytes,
    upload_root="uploads",
    allowed_extensions=(".pdf",),
):
    """发布一次人工书面作业覆盖。

    ``overwrite_record(id, stored_filename, expected_snapshot)`` 必须在同一事务锁定提交、
    比较 expected_snapshot、预占配额并更新指针；文件已经完整可读后才调用它。
    """

    try:
        submission_id = int(previous_submission["id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("缺少有效的旧提交 ID") from exc
    if max_bytes is None or int(max_bytes) <= 0:
        raise ValueError("max_bytes 必须为正整数")
    if load_current_record is None:
        raise ValueError("必须提供提交记录加载器以消除不确定提交结果")

    token = uuid4().hex
    stored_filename = _stored_filename(filename, token)
    paths = _publication_paths(upload_root, submission_id, token, stored_filename)
    paths["lock"].parent.mkdir(parents=True, exist_ok=True)
    paths["upload_staging"].parent.mkdir(parents=True, exist_ok=True)
    paths["archive_staging"].parent.mkdir(parents=True, exist_ok=True)
    paths["upload_staging"].mkdir()
    archive_swap = _DirectorySwap(
        paths["archive_staging"], paths["archive_target"], token=token,
    )
    journal_written = False
    db_committed = False
    data = None

    with paths["lock"].open("a+b") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            uploaded_file.save(paths["staged_file"])
            _validate_staged_file(
                paths["staged_file"],
                filename=filename,
                allowed_extensions=allowed_extensions,
                max_bytes=max_bytes,
            )
            current = load_current_record(submission_id)
            if not current or int(current.get("id") or 0) != submission_id:
                raise LookupError("待覆盖的书面作业提交已变更")

            paths["archive_staging"].mkdir()
            _build_archive_staging(
                paths["archive_staging"],
                staged_file=paths["staged_file"],
                filename=stored_filename,
                previous_submission=current,
                problem=problem,
                user=user,
                classes=classes,
            )
            _write_ready_marker(paths["archive_staging"], token)

            data = {
                "version": JOURNAL_VERSION,
                "token": token,
                "submission_id": submission_id,
                "stored_filename": stored_filename,
                "old_filename": _active_filename(current),
                "sha256": _sha256(paths["staged_file"]),
                "state": "prepared",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            _atomic_write_json(paths["journal"], data)
            journal_written = True

            _install_upload(paths, data["sha256"])
            archive_swap.publish()
            overwrite_record(submission_id, stored_filename, current)
            db_committed = True
            data["state"] = "db_committed"
            _atomic_write_json(paths["journal"], data)

        except Exception as exc:
            compensation_errors = []
            if journal_written and not db_committed:
                observed = None
                try:
                    observed = load_current_record(submission_id)
                except Exception:
                    logger.exception(
                        "无法确认人工作业数据库提交结果，保留 journal 等待恢复",
                        extra={"submission_id": submission_id, "token": token},
                    )
                observed_filename = _active_filename(observed)
                if observed_filename == stored_filename:
                    db_committed = True
                    data["state"] = "db_committed"
                    try:
                        _atomic_write_json(paths["journal"], data)
                    except Exception as journal_exc:
                        compensation_errors.append(journal_exc)
                elif observed is not None and observed_filename == data.get("old_filename"):
                    compensation_errors.extend(
                        _rollback_prepared(paths, data, archive_swap)
                    )
                else:
                    compensation_errors.append(
                        WrittenSubmissionPublicationConflict(
                            "数据库提交结果不确定，已保留 publication journal"
                        )
                    )

            if db_committed:
                cleanup_errors = _cleanup_published(
                    paths, paths["journal"], archive_swap,
                )
                if cleanup_errors:
                    logger.warning(
                        "人工作业已提交，残留产物将由恢复器清理",
                        extra={"submission_id": submission_id, "token": token},
                    )
                _audit_published_submission(
                    submission_id=submission_id,
                    token=token,
                    data=data,
                    destination=paths["upload_destination"],
                    problem=problem,
                    user=user,
                )
                return paths["upload_destination"]

            if not journal_written:
                _remove_path(paths["upload_staging"])
                _remove_path(paths["archive_staging"])
            if compensation_errors:
                message = "新作业发布结果待自动恢复，请稍后刷新"
            else:
                message = "新作业发布失败，已保留上一份有效作业"
            raise WrittenSubmissionArtifactError(
                message,
                compensation_errors=compensation_errors,
            ) from exc
        else:
            cleanup_errors = _cleanup_published(
                paths, paths["journal"], archive_swap,
            )
            if cleanup_errors:
                logger.warning(
                    "人工作业发布成功，残留产物将由恢复器清理",
                    extra={"submission_id": submission_id, "token": token},
                )
            _audit_published_submission(
                submission_id=submission_id,
                token=token,
                data=data,
                destination=paths["upload_destination"],
                problem=problem,
                user=user,
            )
            return paths["upload_destination"]
        finally:
            if not journal_written:
                _remove_path(paths["upload_staging"])
                _remove_path(paths["archive_staging"])


def recover_written_submission_publications(
    load_current_record,
    *,
    upload_root="uploads",
    min_age_seconds=DEFAULT_RECOVERY_GRACE_SECONDS,
    limit=50,
):
    """幂等恢复崩溃遗留的 publication journal。"""

    journal_root = Path(upload_root) / JOURNAL_DIRNAME
    result = {"completed": 0, "rolled_back": 0, "conflicts": 0, "failed": 0}
    if not journal_root.is_dir():
        return result
    now = time.time()
    for journal in sorted(journal_root.glob("*.json"))[: max(0, int(limit))]:
        try:
            if now - journal.stat().st_mtime < max(0, int(min_age_seconds)):
                continue
            data = _validated_journal(journal)
            paths = _publication_paths(
                upload_root,
                data["submission_id"],
                data["token"],
                data["stored_filename"],
            )
            paths["lock"].parent.mkdir(parents=True, exist_ok=True)
            archive_swap = _DirectorySwap(
                paths["archive_staging"],
                paths["archive_target"],
                token=data["token"],
            )
            with paths["lock"].open("a+b") as lock_file:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                current = load_current_record(data["submission_id"])
                observed = _active_filename(current)
                if observed == data["stored_filename"]:
                    data["state"] = "db_committed"
                    _atomic_write_json(paths["journal"], data)
                    errors = _cleanup_published(
                        paths, paths["journal"], archive_swap,
                    )
                    if errors:
                        result["failed"] += 1
                    else:
                        result["completed"] += 1
                elif current is not None and observed == data.get("old_filename"):
                    errors = _rollback_prepared(paths, data, archive_swap)
                    if errors:
                        result["failed"] += 1
                    else:
                        result["rolled_back"] += 1
                else:
                    result["conflicts"] += 1
                    logger.error(
                        "人工作业 publication 与数据库 generation 冲突，拒绝自动覆盖",
                        extra={
                            "submission_id": data["submission_id"],
                            "token": data["token"],
                        },
                    )
        except Exception:
            result["failed"] += 1
            logger.exception("恢复人工作业 publication 失败", extra={"journal": str(journal)})
    return result
