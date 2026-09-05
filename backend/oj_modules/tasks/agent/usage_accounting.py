#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Agent 模型请求的容错计费与宿主持久待办。

模型响应和站内账本属于两个独立故障域。这里先把逐请求价格快照写入容器
不可见的宿主持久 outbox，再幂等提交 MySQL；数据库或配置读取暂时不可用时
只延迟结算，不把计费旁路故障传播给正在运行的 harness。
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import logging
import os
import re
import secrets
import stat
import threading
from typing import Callable

from backend.oj_modules.agents import workspace as agent_workspace
from backend.oj_modules.agents.quota import charge_agent_usage
from backend.oj_modules.site_config.services import (
    DynamicConfigNotFoundError,
    get_llm_endpoint,
)
from backend.oj_modules.tasks.agent.shared import publish_agent_billing_revision


logger = logging.getLogger(__name__)

_OUTBOX_DIRECTORY = ".usage-outbox"
_OUTBOX_VERSION = 1
_MAX_OUTBOX_RECORD_BYTES = 64 * 1024
_OUTBOX_FILENAME_RE = re.compile(r"[0-9a-f]{64}\.json\Z")
_USAGE_FIELDS = (
    "input_uncached_tokens",
    "input_cached_tokens",
    "input_cache_write_tokens",
    "output_tokens",
    "reasoning_output_tokens",
)
_USAGE_AUDIT_FIELDS = (
    "cached_fallback_request_count",
    "cached_fallback_input_tokens",
)
_PRICE_FIELDS = (
    "input_price_per_million",
    "cached_input_price_per_million",
    "output_price_per_million",
)


class AgentUsageOutboxError(RuntimeError):
    """计费 outbox 无法安全读写。"""


@contextmanager
def _open_outbox_directory():
    """沿用 workspace 的 no-follow、0700 宿主私有目录边界。"""

    root_fd = agent_workspace._open_workspace_root_fd()
    outbox_fd = None
    try:
        outbox_fd = agent_workspace._open_managed_child_directory(
            root_fd,
            _OUTBOX_DIRECTORY,
            label="Agent 计费 outbox 目录",
        )
        yield outbox_fd
    finally:
        if outbox_fd is not None:
            os.close(outbox_fd)
        os.close(root_fd)


def _canonical_record_bytes(envelope):
    try:
        payload = json.dumps(
            envelope,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AgentUsageOutboxError("计费待办不是可序列化对象") from exc
    if len(payload) > _MAX_OUTBOX_RECORD_BYTES:
        raise AgentUsageOutboxError("计费待办超过大小限制")
    return payload


def _record_filename(envelope):
    identity = "\0".join((
        str(envelope.get("task_id") or ""),
        str(envelope.get("source") or ""),
        str(envelope.get("usage_event_id") or ""),
    )).encode("utf-8")
    return hashlib.sha256(identity).hexdigest() + ".json"


def _read_record_bytes(directory_fd, filename):
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        file_fd = os.open(filename, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise AgentUsageOutboxError("无法安全打开计费待办") from exc
    try:
        info = os.fstat(file_fd)
        if not stat.S_ISREG(info.st_mode):
            raise AgentUsageOutboxError("计费待办必须是普通文件")
        if info.st_size < 1 or info.st_size > _MAX_OUTBOX_RECORD_BYTES:
            raise AgentUsageOutboxError("计费待办大小无效")
        chunks = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(file_fd, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) != info.st_size:
            raise AgentUsageOutboxError("计费待办读取不完整")
        return payload
    finally:
        os.close(file_fd)


def _persist_record(envelope):
    """以临时文件 + 硬链接发布，绝不覆盖同一幂等键的既有内容。"""

    payload = _canonical_record_bytes(envelope)
    filename = _record_filename(envelope)
    temporary = f".{filename}.{secrets.token_hex(8)}.tmp"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    with _open_outbox_directory() as directory_fd:
        file_fd = None
        try:
            file_fd = os.open(
                temporary,
                flags,
                0o600,
                dir_fd=directory_fd,
            )
            offset = 0
            while offset < len(payload):
                written = os.write(file_fd, payload[offset:])
                if written <= 0:
                    raise AgentUsageOutboxError("计费待办写入不完整")
                offset += written
            os.fsync(file_fd)
            os.close(file_fd)
            file_fd = None
            try:
                os.link(
                    temporary,
                    filename,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                existing = _read_record_bytes(directory_fd, filename)
                if existing != payload:
                    raise AgentUsageOutboxError(
                        "同一计费幂等键对应的待办内容冲突"
                    )
            os.fsync(directory_fd)
        except OSError as exc:
            raise AgentUsageOutboxError("无法持久化计费待办") from exc
        finally:
            if file_fd is not None:
                os.close(file_fd)
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except OSError:
                logger.warning("清理计费 outbox 临时文件失败", exc_info=True)
    return filename


def _replace_record(envelope):
    """原子更新同一幂等键的恢复元数据，例如解除已删除节点的外键。"""

    payload = _canonical_record_bytes(envelope)
    filename = _record_filename(envelope)
    temporary = f".{filename}.{secrets.token_hex(8)}.tmp"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    with _open_outbox_directory() as directory_fd:
        file_fd = None
        try:
            file_fd = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
            offset = 0
            while offset < len(payload):
                written = os.write(file_fd, payload[offset:])
                if written <= 0:
                    raise AgentUsageOutboxError("计费待办写入不完整")
                offset += written
            os.fsync(file_fd)
            os.close(file_fd)
            file_fd = None
            os.replace(
                temporary,
                filename,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            os.fsync(directory_fd)
        except OSError as exc:
            raise AgentUsageOutboxError("无法更新计费待办") from exc
        finally:
            if file_fd is not None:
                os.close(file_fd)
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except OSError:
                logger.warning("清理计费 outbox 临时文件失败", exc_info=True)
    return filename


def _remove_record(filename):
    with _open_outbox_directory() as directory_fd:
        try:
            os.unlink(filename, dir_fd=directory_fd)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise AgentUsageOutboxError("无法移除已结算计费待办") from exc
        os.fsync(directory_fd)


def _load_record(filename):
    if not _OUTBOX_FILENAME_RE.fullmatch(str(filename or "")):
        raise AgentUsageOutboxError("计费待办文件名无效")
    with _open_outbox_directory() as directory_fd:
        payload = _read_record_bytes(directory_fd, filename)
    try:
        envelope = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentUsageOutboxError("计费待办内容损坏") from exc
    if not isinstance(envelope, dict) or envelope.get("version") != _OUTBOX_VERSION:
        raise AgentUsageOutboxError("计费待办版本无效")
    if _record_filename(envelope) != filename:
        raise AgentUsageOutboxError("计费待办身份与文件名不一致")
    return envelope


def _list_record_filenames():
    with _open_outbox_directory() as directory_fd:
        try:
            names = os.listdir(directory_fd)
        except OSError as exc:
            raise AgentUsageOutboxError("无法扫描计费 outbox") from exc
        records = []
        for name in names:
            if not _OUTBOX_FILENAME_RE.fullmatch(name):
                continue
            try:
                info = os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except OSError:
                continue
            if stat.S_ISREG(info.st_mode):
                records.append((info.st_mtime_ns, name))
    return [name for _modified_at, name in sorted(records)]


def _defer_record(filename):
    """把失败记录移到本轮队尾，避免固定坏记录饿死后续待办。"""

    try:
        with _open_outbox_directory() as directory_fd:
            os.utime(
                filename,
                None,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            os.fsync(directory_fd)
    except Exception:
        logger.warning(
            "更新计费待办重试顺序失败",
            extra={"usage_outbox_file": filename},
            exc_info=True,
        )


def _charge_kwargs(envelope):
    required = {
        "user_id",
        "session_id",
        "task_id",
        "source",
        "usage_event_id",
        "endpoint_id",
        "endpoint_revision",
        "endpoint_model",
        "usage",
        "pricing",
        "is_admin",
    }
    if not isinstance(envelope, dict) or not required.issubset(envelope):
        raise AgentUsageOutboxError("计费待办字段不完整")
    result = {field: envelope[field] for field in required}
    if envelope.get("site_funded"):
        result["site_funded"] = True
    return result


def _settle_envelope(envelope, *, charge_usage):
    result = charge_usage(**_charge_kwargs(envelope))
    if not isinstance(result, dict):
        raise AgentUsageOutboxError("计费服务返回了无效结果")
    # applied=False 是已经由相同幂等键完成结算，不是失败。
    if result.get("applied") not in {True, False}:
        raise AgentUsageOutboxError("计费服务没有确认幂等结算状态")
    settled = {
        **result,
        "acknowledged": True,
        "remaining_rmb": result.get("remaining_amount"),
    }
    try:
        billing_revision = int(result.get("id") or 0)
    except (TypeError, ValueError):
        billing_revision = 0
    if billing_revision > 0:
        settled["billing_revision"] = billing_revision
        # MySQL commit 已完成后才会走到这里。通知是低延迟提示，失败时前端
        # 仍会用账本 revision 周期收敛，绝不能把 Redis 异常算作结算失败。
        try:
            publish_agent_billing_revision(
                envelope.get("session_id"),
                envelope.get("task_id"),
                billing_revision,
            )
        except Exception:
            logger.warning(
                "发布 Agent 会话计费 revision 失败；账本结算已经完成",
                extra={
                    "session_id": envelope.get("session_id"),
                    "task_id": envelope.get("task_id"),
                    "billing_revision": billing_revision,
                },
                exc_info=True,
            )
    return settled


def reconcile_agent_usage_outbox(
    *,
    limit=100,
    charge_usage=None,
    endpoint_lookup=None,
):
    """重放宿主持久待办；单条失败不会阻断其余记录或恢复任务。"""

    try:
        normalized_limit = max(1, min(int(limit), 1000))
    except (TypeError, ValueError):
        normalized_limit = 100
    settle = charge_usage or charge_agent_usage
    lookup_endpoint = endpoint_lookup or get_llm_endpoint
    stats = {
        "scanned": 0,
        "settled": 0,
        "hard_stops": 0,
        "failed": 0,
    }
    try:
        filenames = _list_record_filenames()[:normalized_limit]
    except Exception:
        logger.exception("扫描 Agent 计费 outbox 失败；稍后继续重试")
        stats["failed"] = 1
        return stats
    for filename in filenames:
        stats["scanned"] += 1
        try:
            envelope = _load_record(filename)
            endpoint_id = envelope.get("endpoint_id")
            if endpoint_id is not None:
                try:
                    lookup_endpoint(endpoint_id, include_secret=False)
                except DynamicConfigNotFoundError:
                    envelope = {**envelope, "endpoint_id": None}
                    _replace_record(envelope)
                except Exception:
                    # 配置数据库异常时不能猜测节点已删除；继续用已冻结快照
                    # 尝试结算，失败后保留记录即可。
                    pass
            result = _settle_envelope(envelope, charge_usage=settle)
            _remove_record(filename)
        except Exception:
            stats["failed"] += 1
            logger.exception(
                "重放 Agent 计费待办失败；记录保留等待下次重试",
                extra={"usage_outbox_file": filename},
            )
            _defer_record(filename)
            continue
        stats["settled"] += 1
        if bool(result.get("hard_stop")):
            stats["hard_stops"] += 1
    return stats


class ResilientAgentUsageAccountant:
    """单轮任务的非致命计费回调，并在后台短退避重试未结算事件。"""

    def __init__(
        self,
        *,
        user_id,
        session_id,
        task_id,
        endpoint_snapshot,
        is_admin=False,
        site_funded=False,
        endpoint_snapshot_loader: Callable | None = None,
        charge_usage: Callable | None = None,
        on_settled: Callable | None = None,
        start_retry_worker=True,
    ):
        self.user_id = int(user_id)
        self.session_id = str(session_id or "").strip()
        self.task_id = str(task_id or "").strip()
        self.is_admin = bool(is_admin)
        self.site_funded = bool(site_funded)
        self._snapshot = self._normalize_snapshot(endpoint_snapshot)
        self._snapshot_loader = endpoint_snapshot_loader
        self._charge_usage = charge_usage or charge_agent_usage
        self._on_settled = on_settled
        self._pending = {}
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._closed = threading.Event()
        self._hard_stop_callback = None
        self._pending_hard_stop = None
        self._hard_stop_notified = False
        self._retry_thread = None
        if start_retry_worker:
            self._retry_thread = threading.Thread(
                target=self._retry_loop,
                name=f"agent-usage-retry-{self.task_id[:20]}",
                daemon=True,
            )
            self._retry_thread.start()

    @staticmethod
    def _normalize_snapshot(snapshot):
        if not isinstance(snapshot, dict):
            raise AgentUsageOutboxError("计费价格快照无效")
        pricing = snapshot.get("pricing")
        if not isinstance(pricing, dict):
            raise AgentUsageOutboxError("计费价格快照不完整")
        endpoint_id = snapshot.get("endpoint_id")
        return {
            "endpoint_id": None if endpoint_id is None else int(endpoint_id),
            "endpoint_revision": int(snapshot["endpoint_revision"]),
            "endpoint_model": str(snapshot["endpoint_model"] or "").strip(),
            "pricing": {
                field: str(pricing[field]).strip()
                for field in _PRICE_FIELDS
            },
        }

    def set_hard_stop_callback(self, callback):
        with self._lock:
            self._hard_stop_callback = callback if callable(callback) else None
        self._deliver_pending_hard_stop()

    def _current_snapshot(self):
        loader = self._snapshot_loader
        if callable(loader):
            try:
                snapshot = self._normalize_snapshot(loader())
            except Exception:
                logger.warning(
                    "刷新 Agent 计费价格失败；沿用上一份完整价格快照",
                    extra={"task_id": self.task_id},
                    exc_info=True,
                )
            else:
                with self._lock:
                    self._snapshot = snapshot
        with self._lock:
            return {
                **self._snapshot,
                "pricing": dict(self._snapshot["pricing"]),
            }

    def _build_envelope(self, event):
        if not isinstance(event, dict):
            raise AgentUsageOutboxError("模型 usage 事件无效")
        usage = event.get("usage")
        if not isinstance(usage, dict):
            raise AgentUsageOutboxError("模型 usage 计数无效")
        snapshot = self._current_snapshot()
        normalized_usage = {field: usage[field] for field in _USAGE_FIELDS}
        for field in _USAGE_AUDIT_FIELDS:
            if field in usage:
                normalized_usage[field] = usage[field]
        return {
            "version": _OUTBOX_VERSION,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "task_id": self.task_id,
            "source": str(event.get("source") or "").strip().lower(),
            "usage_event_id": str(event.get("id") or "").strip(),
            "endpoint_id": snapshot["endpoint_id"],
            "endpoint_revision": snapshot["endpoint_revision"],
            "endpoint_model": snapshot["endpoint_model"],
            "usage": normalized_usage,
            "pricing": snapshot["pricing"],
            "is_admin": self.is_admin,
            **({"site_funded": True} if self.site_funded else {}),
        }

    def _remember(self, envelope):
        filename = _record_filename(envelope)
        with self._lock:
            self._pending[filename] = envelope
        return filename

    def _forget(self, filename, envelope):
        with self._lock:
            if self._pending.get(filename) is envelope:
                self._pending.pop(filename, None)

    def _notify_settled(self, result):
        if callable(self._on_settled):
            try:
                self._on_settled(result)
            except Exception:
                logger.warning(
                    "刷新 Agent 计费界面投影失败；账本结算已经完成",
                    extra={"task_id": self.task_id},
                    exc_info=True,
                )

    def _notify_hard_stop(self, result):
        with self._lock:
            self._pending_hard_stop = result
        self._deliver_pending_hard_stop()

    def _deliver_pending_hard_stop(self):
        callback = None
        result = None
        with self._lock:
            if (
                self._pending_hard_stop is not None
                and not self._hard_stop_notified
                and callable(self._hard_stop_callback)
            ):
                self._hard_stop_notified = True
                callback = self._hard_stop_callback
                result = self._pending_hard_stop
        if callback is None:
            return
        try:
            callback(result)
        except Exception:
            with self._lock:
                self._hard_stop_notified = False
            logger.exception(
                "投递已结算的额度硬停信号失败；稍后继续重试",
                extra={"task_id": self.task_id},
            )
            if self._retry_thread is not threading.current_thread():
                self._wake.set()

    def _attempt(self, filename, envelope):
        try:
            _persist_record(envelope)
        except Exception:
            # 仍继续尝试数据库；若数据库也不可用，内存副本由后台线程重试。
            logger.exception(
                "持久化 Agent 计费待办失败；保留内存副本继续重试",
                extra={"task_id": self.task_id, "usage_outbox_file": filename},
            )
        try:
            result = _settle_envelope(
                envelope,
                charge_usage=self._charge_usage,
            )
        except Exception:
            # 若配置服务明确确认节点已删除，解除失效外键后立即再试一次；
            # 价格、模型与 revision 仍沿用请求发生时已冻结的审计快照。
            replacement = None
            if envelope.get("endpoint_id") is not None:
                snapshot = self._current_snapshot()
                if snapshot.get("endpoint_id") is None:
                    replacement = {**envelope, "endpoint_id": None}
            if replacement is not None:
                try:
                    _replace_record(replacement)
                except Exception:
                    logger.warning(
                        "更新已删除节点的计费待办失败；保留内存副本重试",
                        extra={"task_id": self.task_id},
                        exc_info=True,
                    )
                with self._lock:
                    if self._pending.get(filename) is envelope:
                        self._pending[filename] = replacement
                envelope = replacement
                try:
                    result = _settle_envelope(
                        envelope,
                        charge_usage=self._charge_usage,
                    )
                except Exception:
                    logger.exception(
                        "Agent usage 暂未结算；任务继续运行并后台重试",
                        extra={
                            "task_id": self.task_id,
                            "usage_outbox_file": filename,
                        },
                    )
                    return None
            else:
                logger.exception(
                    "Agent usage 暂未结算；任务继续运行并后台重试",
                    extra={
                        "task_id": self.task_id,
                        "usage_outbox_file": filename,
                    },
                )
                return None
        try:
            _remove_record(filename)
        except Exception:
            # MySQL 已经提交，保留文件只会触发安全的幂等重放。
            logger.warning(
                "移除已结算 Agent 计费待办失败；稍后将幂等重放",
                extra={"task_id": self.task_id, "usage_outbox_file": filename},
                exc_info=True,
            )
        self._forget(filename, envelope)
        self._notify_settled(result)
        return result

    def __call__(self, event):
        try:
            envelope = self._build_envelope(event)
            filename = self._remember(envelope)
            result = self._attempt(filename, envelope)
        except Exception:
            # 计费事件自身异常也不能成为 harness 的熔断器；日志保留现场，
            # 后续事件和周期恢复仍可继续工作。
            logger.exception(
                "Agent usage 事件处理失败；已与任务生命周期解耦",
                extra={"task_id": self.task_id},
            )
            self._wake.set()
            return {
                "applied": False,
                "acknowledged": True,
                "deferred": True,
                "hard_stop": False,
                "remaining_rmb": None,
            }
        if result is None:
            self._wake.set()
            return {
                "applied": False,
                "acknowledged": True,
                "deferred": True,
                "hard_stop": False,
                "remaining_rmb": None,
            }
        return result

    def retry_pending_once(self):
        with self._lock:
            pending = tuple(self._pending.items())
        settled = 0
        for filename, envelope in pending:
            result = self._attempt(filename, envelope)
            if result is None:
                continue
            settled += 1
            if bool(result.get("hard_stop")):
                self._notify_hard_stop(result)
        self._deliver_pending_hard_stop()
        return {"pending": len(pending) - settled, "settled": settled}

    def _retry_loop(self):
        delay = 1.0
        timeout = None
        while not self._closed.is_set():
            self._wake.wait(timeout=timeout)
            self._wake.clear()
            if self._closed.is_set():
                break
            self.retry_pending_once()
            with self._lock:
                pending_remains = bool(self._pending)
                hard_stop_pending = (
                    self._pending_hard_stop is not None
                    and not self._hard_stop_notified
                )
            if not pending_remains and not hard_stop_pending:
                delay = 1.0
                timeout = None
            else:
                timeout = delay
                delay = min(delay * 2, 30.0)

    def close(self):
        self._closed.set()
        self._wake.set()
        thread = self._retry_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1.0)


__all__ = [
    "AgentUsageOutboxError",
    "ResilientAgentUsageAccountant",
    "reconcile_agent_usage_outbox",
]
