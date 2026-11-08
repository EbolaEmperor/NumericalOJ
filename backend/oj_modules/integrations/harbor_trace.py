"""将官方 Harbor 轨迹导入既有 Judge 会话；不执行 Agent 或修改任务指令。"""

from __future__ import annotations

from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import re
import stat
import tempfile


MAX_TRACE_BYTES = 64 * 1024 * 1024
MAX_EVENT_BYTES = 8 * 1024 * 1024
MAX_PREVIEW_BYTES = 1024 * 1024
_SENSITIVE_KEYS = frozenset({
    "apikey", "authorization", "password", "passwd", "secret", "token",
    "accesstoken", "refreshtoken", "credential", "credentials", "cookie",
    "setcookie", "xapikey", "proxyauthorization",
})
_BEARER = re.compile(r"(?i)\b(Bearer\s+)[^\s\"'<>]+")
_PROVIDER_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b")
_URL_AUTH = re.compile(r"(https?://)[^\s/@:]+:[^\s/@]+@", re.IGNORECASE)
_SECRET_ASSIGNMENT = re.compile(
    r'''(?i)\b([a-z0-9_]*(?:api_key|access_token|auth_token|password)\s*=\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s]+)'''
)
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)


class HarborTraceImportError(ValueError):
    """官方轨迹不能完整导入，调用方须保留执行现场。"""


def redact_harbor_value(value, secrets=()):
    """递归脱敏原始字段及正文；不删除 usage 中的 token 计数。"""
    sensitive_values = tuple(str(secret) for secret in secrets if secret)

    def clean(item):
        if isinstance(item, str):
            for secret in sorted(sensitive_values, key=len, reverse=True):
                item = item.replace(secret, "[REDACTED]")
            item = _BEARER.sub(r"\1[REDACTED]", item)
            item = _PROVIDER_KEY.sub("[REDACTED]", item)
            item = _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", item)
            return _URL_AUTH.sub(r"\1[REDACTED]@", item)
        if isinstance(item, (list, tuple)):
            return [clean(child) for child in item]
        if isinstance(item, dict):
            return {
                clean(str(key)): ("[REDACTED]" if re.sub(r"[^a-z]", "", str(key).lower())
                                  in _SENSITIVE_KEYS else clean(child))
                for key, child in item.items()
            }
        return item

    return clean(value)


def _content(value):
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(
            str(part.get("text") or part.get("thinking") or "")
            if isinstance(part, dict) else str(part)
            for part in value
        )
    if isinstance(value, dict) and value.get("type") in {"text", "thinking"}:
        return str(value.get("text") or value.get("thinking") or "")
    return "" if value is None else json.dumps(value, ensure_ascii=False)


def _json(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def _after_initial_user(entries, is_user):
    for index, entry in enumerate(entries):
        if is_user(entry):
            return entries[index + 1:]
    return []


def _safe_component(name):
    if not isinstance(name, str) or not name or name in {".", ".."} or any(char in name for char in ("/", "\\", "\x00")):
        raise HarborTraceImportError("Harbor 轨迹路径必须使用单个安全文件名")
    return name


@contextmanager
def _open_directories(root_fd, parts, *, missing_ok=False):
    """沿已固定的目录 fd 打开；与 workspace 的 openat 边界一致，不导入站点配置。"""
    opened = []
    current = root_fd
    try:
        for part in parts:
            try:
                descriptor = os.open(_safe_component(part), _DIRECTORY_FLAGS, dir_fd=current)
            except FileNotFoundError:
                if missing_ok:
                    current = None
                    break
                raise
            except OSError as exc:
                raise HarborTraceImportError("Harbor 轨迹父目录不安全，不能跟随符号链接或特殊文件") from exc
            opened.append(descriptor)
            current = descriptor
        yield current
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)


class HarborTraceImporter:
    """读取官方输出快照；实时预览可替换，终态必须完整或明确失败。

    ``emit`` 接收既有 ``trace``/``native`` 消息。trace.records 是完整快照，
    由 trace_store 在事务内替换同一任务的旧预览，稳定 ID 不依赖文件摘要。
    """

    def __init__(self, agent_dir, *, secrets=(), emit):
        self.agent_dir = Path(agent_dir)
        self.secrets = tuple(secrets)
        self.emit = emit
        self.native_session_id = ""
        self.import_manifest = None
        self._previous = None

    def _read_at(self, directory_fd, name, budget):
        try:
            descriptor = os.open(_safe_component(name), _FILE_FLAGS, dir_fd=directory_fd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise HarborTraceImportError("Harbor 轨迹不能包含符号链接") from exc
            raise
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise HarborTraceImportError("Harbor 轨迹必须是普通文件")
            if metadata.st_size > budget:
                raise HarborTraceImportError("Harbor 完整轨迹超过 64 MiB 导入限额，已保留原始文件")
            raw = source.read(budget + 1)
        if len(raw) > budget:
            raise HarborTraceImportError("Harbor 轨迹在读取时超过导入限额")
        return raw.decode("utf-8"), len(raw)

    def _read(self, path, budget):
        parts = Path(path).relative_to(self.agent_dir).parts
        if not parts:
            raise HarborTraceImportError("Harbor 轨迹必须是普通文件")
        root_fd = os.open(self.agent_dir, _DIRECTORY_FLAGS)
        try:
            with _open_directories(root_fd, parts[:-1]) as parent_fd:
                return self._read_at(parent_fd, parts[-1], budget)
        finally:
            os.close(root_fd)

    def _load(self):
        root_fd = os.open(self.agent_dir, _DIRECTORY_FLAGS)
        try:
            return self._load_at(root_fd)
        finally:
            os.close(root_fd)

    def _load_at(self, root_fd):
        budget = MAX_TRACE_BYTES
        trajectory = None
        try:
            raw, count = self._read_at(root_fd, "trajectory.json", budget)
        except FileNotFoundError:
            pass
        else:
            budget -= count
            trajectory = json.loads(raw)
            if not isinstance(trajectory, dict) or not isinstance(trajectory.get("steps"), list):
                raise HarborTraceImportError("Harbor ATIF 轨迹格式无效")
            if any(not isinstance(step, dict) for step in trajectory["steps"]):
                raise HarborTraceImportError("Harbor ATIF 步骤格式无效")
        native = []
        with _open_directories(root_fd, ("pi", "sessions"), missing_ok=True) as sessions_fd:
            if sessions_fd is not None:
                names = sorted(_safe_component(name) for name in os.listdir(sessions_fd) if name.endswith(".jsonl"))
                if len(names) > 4096:
                    raise HarborTraceImportError("Harbor 原生会话文件数量超过 4096 个")
                for name in names:
                    raw, count = self._read_at(sessions_fd, name, budget)
                    budget -= count
                    entries = []
                    for index, line in enumerate(raw.splitlines(), 1):
                        if not line.strip():
                            continue
                        entry = json.loads(line)
                        if not isinstance(entry, dict):
                            raise HarborTraceImportError("Harbor 原生会话事件格式无效")
                        entries.append((index, entry))
                    native.append(("pi/sessions/" + name, entries))
        if trajectory is None and not native:
            raise HarborTraceImportError("Harbor 未生成可导入的完整会话轨迹")
        return redact_harbor_value({"trajectory": trajectory, "native": native}, self.secrets)

    def _records(self, snapshot):
        trajectory = snapshot["trajectory"] or {}
        session_id = str(trajectory.get("session_id") or "")
        if session_id == "unknown":
            session_id = ""
        for _, entries in snapshot["native"]:
            for _, entry in entries:
                if entry.get("type") == "session" and entry.get("id"):
                    session_id = session_id or str(entry["id"])
                    break
        if not session_id or len(session_id) > 256:
            raise HarborTraceImportError("Harbor 官方会话 ID 缺失或无效")
        original_steps = trajectory.get("steps", [])
        steps = _after_initial_user(original_steps, lambda step: step.get("source") == "user")
        native = [(filename, _after_initial_user(entries, lambda item:
                   item[1].get("type") == "message"
                   and isinstance(item[1].get("message"), dict)
                   and item[1]["message"].get("role") == "user"))
                  for filename, entries in snapshot["native"]]
        counts = {
            "atif_steps": len(original_steps), "native_files": len(native),
            "native_events": sum(len(entries) for _, entries in snapshot["native"]),
            "skipped_initial_atif_steps": len(original_steps) - len(steps),
            "skipped_initial_native_events": sum(len(entries) for _, entries in snapshot["native"])
                                             - sum(len(entries) for _, entries in native),
        }
        records = []
        used_ids = set()

        def add(identity, kind, title, text, payload, *, error=False, role=None):
            if not text:
                text = "（无正文；完整原始字段见来源信息）"
            if identity in used_ids or len(identity) > 512:
                raise HarborTraceImportError("Harbor 原始事件 ID 重复或过长")
            used_ids.add(identity)
            event = {"id": identity, "kind": kind, "title": title, "text": text,
                     "format": "text", "is_error": bool(error),
                     "source_payload": payload, "role": role or kind}
            record = {"version": 1, "type": "numoj_trace", "sequence": len(records) + 1,
                      "source": "harbor", "full_text": True, "replace_snapshot": True,
                      "snapshot_id": session_id, "event": event}
            if len(_json(record).encode()) > MAX_EVENT_BYTES:
                raise HarborTraceImportError("Harbor 单个完整事件超过 8 MiB 导入限额，已保留原始文件")
            records.append(record)

        steps_by_native_id = {}
        for step in steps:
            native_id = (step.get("extra") or {}).get("pi_event_id")
            if native_id:
                steps_by_native_id.setdefault(str(native_id), []).append(step)

        if snapshot["native"]:
            attached_steps = set()
            for (filename, entries), (_, original_entries) in zip(native, snapshot["native"]):
                native_session = next((str(entry["id"]) for _, entry in original_entries
                                       if entry.get("type") == "session" and entry.get("id")), filename)
                for line, entry in entries:
                    event_id = str(entry.get("id") or f"line-{line}")
                    base = f"harbor:pi:{native_session}:{event_id}"
                    payload = {"native_file": filename, "native_line": line, "native_event": entry}
                    if event_id in steps_by_native_id:
                        payload["atif_steps"] = steps_by_native_id[event_id]
                        attached_steps.add(event_id)
                    message = entry.get("message")
                    if entry.get("type") != "message" or not isinstance(message, dict):
                        text = _content(entry.get("summary") or entry.get("content")) or str(entry.get("type") or "事件")
                        add(base, "system", "原生会话事件", text, payload, role="system")
                        continue
                    role = str(message.get("role") or "system")
                    if role == "toolResult":
                        add(base, "tool_result", str(message.get("toolName") or "工具结果"),
                            _content(message.get("content")), payload,
                            error=message.get("isError"), role=role)
                        continue
                    blocks = message.get("content")
                    if not isinstance(blocks, list):
                        blocks = [{"type": "text", "text": _content(blocks)}]
                    if not blocks:
                        blocks = [{"type": "text", "text": message.get("errorMessage") or ""}]
                    for index, block in enumerate(blocks):
                        if not isinstance(block, dict):
                            block = {"type": "text", "text": str(block)}
                        block_type = block.get("type")
                        details = payload if index == 0 else {"native_event_id": event_id,
                            "native_file": filename, "content_index": index, "block": block}
                        error = message.get("stopReason") in {"error", "aborted"}
                        if block_type in {"thinking", "reasoning"}:
                            kind, title, text = "thinking", "思考", str(block.get("thinking") or block.get("reasoning") or block.get("text") or "")
                        elif block_type == "toolCall":
                            kind, title, text = "tool_call", str(block.get("name") or "工具调用"), _json(block.get("arguments") or {})
                        else:
                            kind = "assistant" if role == "assistant" else "user" if role == "user" else "system"
                            title = "回复" if kind == "assistant" else "任务指令" if kind == "user" else "系统消息"
                            text = _content(block)
                            if not text and block_type not in {None, "text"}:
                                text = _json(block)
                        add(base + f":content:{index}", kind, title, text, details, error=error, role=role)
                    if message.get("errorMessage"):
                        add(base + ":error", "error", "Agent 错误", str(message["errorMessage"]),
                            {"native_event_id": event_id, "stop_reason": message.get("stopReason")}, error=True, role=role)
            # ATIF 中没有对应原生消息的内容仍需保留，例如压缩摘要和补充指标。
            for step in steps:
                native_id = str((step.get("extra") or {}).get("pi_event_id") or "")
                if native_id not in attached_steps:
                    add("harbor:atif-source:" + str(step.get("step_id")), "system", "ATIF 来源记录",
                        "官方 ATIF 补充记录", {"atif_step": step}, role=str(step.get("source") or "system"))
        else:
            for step in steps:
                base = "harbor:step:" + str(step.get("step_id"))
                role = str(step.get("source") or "system")
                payload = {"atif_step": step}
                if step.get("reasoning_content"):
                    add(base + ":thinking", "thinking", "思考", _content(step["reasoning_content"]), payload, role=role)
                    payload = {"atif_step_id": step.get("step_id")}
                if step.get("message") or not step.get("tool_calls") and not step.get("reasoning_content"):
                    kind = "assistant" if role == "agent" else "user" if role == "user" else "system"
                    add(base + ":message", kind, "回复" if kind == "assistant" else "任务指令" if kind == "user" else "系统消息",
                        _content(step.get("message")), payload, role=role)
                    payload = {"atif_step_id": step.get("step_id")}
                for index, call in enumerate(step.get("tool_calls") or []):
                    call_id = str(call.get("tool_call_id") or index)
                    add(base + ":call:" + call_id, "tool_call", str(call.get("function_name") or "工具调用"),
                        _json(call.get("arguments") or {}), {**payload, "tool_call": call}, role=role)
                    payload = {"atif_step_id": step.get("step_id")}
                for index, result in enumerate((step.get("observation") or {}).get("results") or []):
                    call_id = str(result.get("source_call_id") or index)
                    add(base + f":result:{index}:" + call_id, "tool_result", "工具结果", _content(result.get("content")),
                        {"atif_step_id": step.get("step_id"), "observation": result},
                        error=(result.get("extra") or {}).get("is_error"), role="toolResult")
        if sum(len(_json(record).encode()) for record in records) > MAX_TRACE_BYTES:
            raise HarborTraceImportError("Harbor 完整导入记录超过 64 MiB，已保留原始文件")
        return session_id, records, counts

    def sync(self, *, final=False):
        """预览返回 bool；最终成功返回已落盘的完整性 manifest。"""
        manifest_path = self.agent_dir / "numoj-import-manifest.json"
        if final:
            if manifest_path.is_symlink():
                raise HarborTraceImportError("Harbor 导入记录不能是符号链接")
            manifest_path.unlink(missing_ok=True)
        try:
            snapshot = self._load()
            session_id, records, counts = self._records(snapshot)
        except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
            if final:
                if isinstance(exc, HarborTraceImportError):
                    raise
                raise HarborTraceImportError("Harbor 完整会话读取或解析失败，已保留原始文件") from exc
            return False
        if session_id != self.native_session_id:
            self.native_session_id = session_id
            self.emit({"type": "native", "session_id": session_id})
        if not final and (snapshot == self._previous or len(_json(records).encode()) > MAX_PREVIEW_BYTES):
            return False
        if not final and not records:
            self._previous = snapshot
            return False
        counts["imported_events"] = len(records)
        preserved_steps = set()
        preserved_native = set()
        for record in records:
            event = record["event"]
            source = event["source_payload"]
            if "native_event" in source:
                preserved_native.add((source["native_file"], source["native_line"]))
            for step in ([source["atif_step"]] if "atif_step" in source else source.get("atif_steps", [])):
                preserved_steps.add(str(step.get("step_id")))
        if (len(preserved_native) + counts["skipped_initial_native_events"] != counts["native_events"]
                or len(preserved_steps) + counts["skipped_initial_atif_steps"] != counts["atif_steps"]):
            raise HarborTraceImportError("Harbor 完整会话来源计数不一致，已保留原始文件")
        counts["preserved_native_events"] = len(preserved_native)
        counts["preserved_atif_steps"] = len(preserved_steps)
        if records:
            records[0]["event"]["source_payload"]["import"] = {"complete": bool(final), "counts": counts}
            if len(_json(records[0]).encode()) > MAX_EVENT_BYTES:
                raise HarborTraceImportError("Harbor 会话信息超过 8 MiB 导入限额")
        if sum(len(_json(record).encode()) for record in records) > MAX_TRACE_BYTES:
            raise HarborTraceImportError("Harbor 完整导入记录超过 64 MiB，已保留原始文件")
        self.emit({"type": "trace", "records": records, "final": final,
                   "complete": bool(final), "snapshot_id": session_id, "counts": counts})
        self._previous = snapshot
        if final:
            # emit 的同步回调必须成功提交主站轨迹事务，才能声称导入完整。
            manifest = {"schema": "numoj-harbor-import-v1", "complete": True,
                        "mode": "native-pi+atif" if snapshot["native"] else "atif",
                        "session_id": session_id, "events_expected": len(records),
                        "events_imported": len(records), "counts": counts,
                        "source_event_ids": [record["event"]["id"] for record in records]}
            serialized = _json(manifest)
            if len(serialized.encode()) > MAX_EVENT_BYTES:
                raise HarborTraceImportError("Harbor 完整导入记录清单超过 8 MiB，已保留原始文件")
            temporary = None
            try:
                descriptor, temporary = tempfile.mkstemp(prefix=".numoj-import-", dir=self.agent_dir)
                with os.fdopen(descriptor, "w", encoding="utf-8") as target:
                    target.write(serialized)
                os.replace(temporary, manifest_path)
                temporary = None
            finally:
                if temporary is not None:
                    Path(temporary).unlink(missing_ok=True)
            self.import_manifest = manifest
            return manifest
        return True
