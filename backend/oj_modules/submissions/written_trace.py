"""书面评委的私有逐轮工件；不混入普通日志，不向学生详情投影。"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import uuid

from backend.oj_modules.ai.exchange_capture import capture_exchanges
from backend.oj_modules.project_paths import PROJECT_ROOT


TRACE_ROOT = PROJECT_ROOT / "written_grading_traces"
_RECORD_ID = re.compile(r"^[0-9a-f]{32}$")
_ARTIFACT = re.compile(r"^(round\.json|call-[1-9][0-9]*\.(json|request\.json|response\.body))$")


class WrittenGradingTraceError(RuntimeError):
    """记录无法安全保存时明确失败，不能静默继续一个无法追查的评分。"""


def _now():
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def _writing():
    try:
        yield
    except OSError:
        raise WrittenGradingTraceError("书面评分记录写入失败，请检查私有工件目录和磁盘空间。") from None


def _directory(*parts, create=False):
    path = Path(TRACE_ROOT)
    for part in (None, *parts):
        if part is not None:
            path /= str(part)
        if path.is_symlink():
            raise WrittenGradingTraceError("书面评分记录目录不能是符号链接。")
        if path.exists() and not path.is_dir():
            raise WrittenGradingTraceError("书面评分记录目录无效。")
        if create:
            with _writing():
                path.mkdir(mode=0o700, exist_ok=True)
    return path


def _write_json(path, payload):
    temporary = path.with_name(path.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    with _writing():
        with os.fdopen(os.open(temporary, flags, 0o600), "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, allow_nan=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)


def _read_json(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), encoding="utf-8") as stream:
        return json.load(stream)


class _Exchange:
    def __init__(self, directory, number, payload, purpose):
        self.directory = directory
        self.prefix = f"call-{number}"
        self.metadata = {
            "number": number, "purpose": purpose, "status": "pending",
            "started_at": _now(), "body_complete": False,
            "request_file": f"{self.prefix}.request.json",
            "response_file": f"{self.prefix}.response.body",
        }
        # 与 requests 的 json= 编码一致；响应返回后优先保存 PreparedRequest 的实际 body。
        body = json.dumps(payload, allow_nan=False).encode("utf-8")
        self._write_request(body)
        with _writing():
            self.stream = os.fdopen(os.open(
                directory / self.metadata["response_file"],
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
            ), "wb", buffering=0)
        try:
            self._save()
        except BaseException:
            self.stream.close()
            raise

    def _save(self):
        _write_json(self.directory / f"{self.prefix}.json", self.metadata)

    def _write_request(self, body):
        path = self.directory / self.metadata["request_file"]
        temporary = path.with_name(path.name + ".tmp")
        with _writing():
            with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600), "wb") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)

    def received(self, response):
        body = getattr(getattr(response, "request", None), "body", None)
        if isinstance(body, str):
            body = body.encode("utf-8")
        if isinstance(body, bytes):
            self._write_request(body)
        self.metadata.update(
            status="receiving", http_status=int(response.status_code),
            content_type=str(response.headers.get("Content-Type", "")),
        )
        self._save()

    def write(self, chunk):
        if not isinstance(chunk, bytes):
            raise WrittenGradingTraceError("书面评分响应记录必须是字节。")
        with _writing():
            remaining = memoryview(chunk)
            while remaining:
                written = self.stream.write(remaining)
                if not written:
                    raise WrittenGradingTraceError("书面评分响应记录未能完整写入。")
                remaining = remaining[written:]

    def body_complete(self):
        self.metadata["body_complete"] = True
        self._save()

    def failed(self, kind):
        self.metadata.update(status="failed", error_type=kind)
        self.close()

    def close(self):
        if not self.stream.closed:
            try:
                with _writing():
                    os.fsync(self.stream.fileno())
            finally:
                self.stream.close()
        if self.metadata["status"] != "failed":
            self.metadata["status"] = "received" if self.metadata["body_complete"] else "incomplete"
        self.metadata["ended_at"] = _now()
        self._save()


class WrittenVoteTrace:
    def __init__(self, submission_id, attempt_id, vote, round_number, call_attempt):
        self.record_id = uuid.uuid4().hex
        self.directory = _directory(int(submission_id), self.record_id, create=True)
        self.calls = []
        self.metadata = {
            "schema_version": 1,
            "record_id": self.record_id, "submission_id": int(submission_id),
            "attempt_id": int(attempt_id), "vote_index": int(vote["vote_index"]),
            "round_number": int(round_number), "call_attempt": int(call_attempt),
            "endpoint_id": vote.get("endpoint_id"), "endpoint_revision": vote.get("endpoint_revision"),
            "model": vote.get("model"), "status": "running", "started_at": _now(),
        }
        self._save()

    def _save(self):
        _write_json(self.directory / "round.json", self.metadata)

    def begin_exchange(self, payload, purpose):
        call = _Exchange(self.directory, len(self.calls) + 1, payload, purpose)
        self.calls.append(call)
        return call

    def completed(self, result):
        if hasattr(result, "raw_response"):
            payload = {
                "score": result.score, "comment": result.comment,
                "raw_response": result.raw_response, "peer_replies": result.peer_replies,
            }
        else:
            score, comment = result
            payload = {"score": int(score), "comment": str(comment)}
        self.metadata.update(status="completed", result=payload)

    @contextmanager
    def capture(self):
        try:
            with capture_exchanges(self):
                yield self
        except BaseException as error:
            self.metadata.update(status="failed", error_type=type(error).__name__)
            raise
        finally:
            for call in self.calls:
                call.close()
            self.metadata["ended_at"] = _now()
            self._save()


def list_submission_traces(submission_id):
    directory = _directory(int(submission_id))
    if not directory.exists():
        return []
    records = []
    for item in directory.iterdir():
        if not _RECORD_ID.fullmatch(item.name) or item.is_symlink():
            continue
        record_dir = _directory(int(submission_id), item.name)
        if not (record_dir / "round.json").exists():
            continue
        record = _read_json(record_dir / "round.json")
        record["calls"] = []
        for path in record_dir.glob("call-*.json"):
            if re.fullmatch(r"call-[1-9][0-9]*\.json", path.name):
                call = _read_json(path)
                response = record_dir / call["response_file"]
                call["response_bytes"] = response.stat().st_size if response.exists() else 0
                record["calls"].append(call)
        record["calls"].sort(key=lambda call: call["number"])
        records.append(record)
    return sorted(records, key=lambda row: (row["attempt_id"], row["round_number"], row["vote_index"], row["call_attempt"], row["started_at"]))


def open_trace_artifact(submission_id, record_id, filename):
    if not _RECORD_ID.fullmatch(record_id) or not _ARTIFACT.fullmatch(filename):
        raise ValueError("评分记录标识或文件名无效。")
    path = _directory(int(submission_id), record_id) / filename
    return os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb")
