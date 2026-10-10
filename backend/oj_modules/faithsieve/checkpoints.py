"""按确定调用顺序保存原文请求和响应，供 Celery 重入时逐步恢复。"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
import re
import tempfile
import stat
from contextlib import contextmanager

from .artifacts import FaithSieveProtocolError, _reject_json_constant, _unique_json_object


_MAX_RECORD_BYTES = 32 * 1024 * 1024
_KEY = re.compile(r"(?:image-render|image-graph-repair-policy|image-graph-context-revision|image-verification-method-policy|source-extraction|final-scoring|role-[0-9]{6,}-attempt-[12]|compile-[0-9]{6,})\Z")


def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".checkpoint-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class CheckpointStore:
    def __init__(self, workspace):
        self.root = Path(workspace).resolve()
        self.directory = self.root / "faithsieve-work" / "checkpoints"
        if not self.directory.resolve().is_relative_to(self.root):
            raise FaithSieveProtocolError("FaithSieve checkpoint 路径越界")
        self._next_sequence = None

    def _path(self, key):
        if not isinstance(key, str) or not _KEY.fullmatch(key):
            raise FaithSieveProtocolError("FaithSieve checkpoint 调用编号无效")
        path = self.directory / f"{key}.json"
        if not path.resolve().is_relative_to(self.root):
            raise FaithSieveProtocolError("FaithSieve checkpoint 路径越界")
        return path

    def get(self, key, request, *, completed_legacy_request=None, completed_legacy_requests=()):
        self._path(key)
        try:
            record, _size = self._read_record(key)
        except FileNotFoundError:
            return None
        legacy_requests = tuple(completed_legacy_requests)
        if completed_legacy_request is not None:
            legacy_requests += (completed_legacy_request,)
        # 只重放完整输入一致的已完成旧协议记录，pending 和失败记录不能换协议继续。
        legacy_completed = (isinstance(record, dict) and record.get("state") == "completed"
                            and any(record.get("request") == candidate for candidate in legacy_requests))
        if not isinstance(record, dict) or (record.get("request") != request and not legacy_completed):
            raise FaithSieveProtocolError("FaithSieve 重入请求与已保存的完整输入不一致")
        if record.get("state") not in {"pending", "completed", "protocol_error", "endpoint_error"}:
            raise FaithSieveProtocolError("FaithSieve checkpoint 状态无效")
        return record

    @contextmanager
    def _open_directory(self):
        opened = []
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(self.root, flags)
            opened.append(fd)
            for part in ("faithsieve-work", "checkpoints"):
                fd = os.open(part, flags, dir_fd=fd)
                opened.append(fd)
            yield fd
        except FileNotFoundError:
            raise
        except OSError:
            raise FaithSieveProtocolError("FaithSieve checkpoint 目录无法安全读取") from None
        finally:
            for fd in reversed(opened):
                os.close(fd)

    def _read_record(self, key, *, strict=False):
        self._path(key)
        fd = None
        try:
            with self._open_directory() as directory_fd:
                fd = os.open(f"{key}.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > _MAX_RECORD_BYTES:
                raise FaithSieveProtocolError("FaithSieve checkpoint 不是受限的独立普通文件")
            with os.fdopen(fd, "rb") as stream:
                fd = None
                data = stream.read(_MAX_RECORD_BYTES + 1)
                if len(data) > _MAX_RECORD_BYTES or os.fstat(stream.fileno()).st_nlink != 1:
                    raise FaithSieveProtocolError("FaithSieve checkpoint 超出安全边界")
            payload = (json.loads(data.decode("utf-8"), object_pairs_hook=_unique_json_object,
                                  parse_constant=_reject_json_constant)
                       if strict else json.loads(data.decode("utf-8")))
            return payload, info.st_size
        except FileNotFoundError:
            raise
        except (OSError, ValueError, UnicodeError) as exc:
            if isinstance(exc, FaithSieveProtocolError):
                raise
            raise FaithSieveProtocolError("FaithSieve checkpoint 无法安全解析") from None
        finally:
            if fd is not None:
                os.close(fd)

    def put(self, key, request, *, state, response=None, error=None, metadata=None):
        path = self._path(key)
        previous = self.get(key, request)
        now = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        payload = {"request": request, "state": state}
        sequence = (previous or {}).get("sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
            if self._next_sequence is None:
                next_sequence = 1
                try:
                    with self._open_directory() as directory_fd:
                        names = os.listdir(directory_fd)
                except FileNotFoundError:
                    names = []
                keys = [name[:-5] for name in names if name.endswith(".json") and _KEY.fullmatch(name[:-5])]
                for saved_key in keys:
                    saved, _size = self._read_record(saved_key)
                    saved_sequence = saved.get("sequence") if isinstance(saved, dict) else None
                    if isinstance(saved_sequence, int) and not isinstance(saved_sequence, bool):
                        next_sequence = max(next_sequence, saved_sequence + 1)
                self._next_sequence = next_sequence
            sequence = self._next_sequence
            self._next_sequence += 1
        payload.update(sequence=sequence, created_at=(previous or {}).get("created_at") or now, updated_at=now)
        if metadata is not None or (previous or {}).get("metadata") is not None:
            payload["metadata"] = metadata if metadata is not None else previous["metadata"]
        if response is not None:
            payload["response"] = response
        if error is not None:
            payload["error"] = str(error)
        data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        if len(data) > _MAX_RECORD_BYTES:
            raise FaithSieveProtocolError("FaithSieve checkpoint 过大")
        atomic_write(path, data)

    def read_records(self):
        """只读核对历史库存，不把枚举视为完整请求已重放。"""
        with self._open_directory() as directory_fd:
            names = os.listdir(directory_fd)
        keys = [name[:-5] for name in names if name.endswith(".json")]
        if len(keys) > 10000 or any(not _KEY.fullmatch(key) for key in keys):
            raise FaithSieveProtocolError("FaithSieve checkpoint 列表无效")
        result, size = {}, 0
        for key in sorted(keys):
            record, count = self._read_record(key, strict=True)
            size += count
            if size > 128 * 1024 * 1024:
                raise FaithSieveProtocolError("FaithSieve 恢复材料超过大小限制")
            if not isinstance(record, dict) or not isinstance(record.get("request"), dict):
                raise FaithSieveProtocolError("FaithSieve checkpoint 结构无效")
            if record.get("state") not in {"pending", "completed", "protocol_error", "endpoint_error"}:
                raise FaithSieveProtocolError("FaithSieve checkpoint 状态无效")
            result[key] = record
        return result

    def records(self):
        """受限列举历史，并沿用调用者的逐项请求校验。"""
        result = self.read_records()
        for key, record in result.items():
            self.get(key, record["request"])
        return result

    def preserve_pdf(self, pdf):
        path = self.root / "submission.pdf"
        if not path.resolve().is_relative_to(self.root):
            raise FaithSieveProtocolError("FaithSieve 原 PDF 路径越界")
        if path.exists():
            if path.read_bytes() != pdf:
                raise FaithSieveProtocolError("FaithSieve 重入的原 PDF 与已保存文件不一致")
        else:
            atomic_write(path, pdf)
