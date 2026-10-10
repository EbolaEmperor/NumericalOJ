"""FaithSieve 的真实调用费用；只读汇总不回填历史、不重算旧价格。"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import json
import logging
import os
from pathlib import Path
import re
import secrets
import stat

from backend.oj_modules.agents.quota import calculate_agent_usage_charge
from backend.oj_modules.agents.trace_store import AGENT_TRACE_SCHEMA_VERSION
from backend.oj_modules.infrastructure.mysql import get_db_connection
from backend.oj_modules.problems.agent_launch import token_pricing_snapshot_from_endpoint

from .artifacts import _reject_json_constant, _unique_json_object
from .cost_outbox import read_pending_usage_events
from . import views


logger = logging.getLogger(__name__)
COST_PATH = "faithsieve-work/cost-events.json"
_ATTEMPT = re.compile(r"[a-f0-9]{32}\Z")
_KEY = re.compile(r"(?:role-[0-9]{6,}-attempt-[12]|final-scoring)\Z")
_MAX_BYTES = 4 * 1024 * 1024
_KINDS = {"role", "json_repair", "empty_result_retry"}
_PRICE_FIELDS = ("input_price_per_million", "cached_input_price_per_million", "output_price_per_million")


def unknown_cost():
    return {"cost_rmb": None, "currency": "CNY", "complete": False,
            "estimated": False, "missing_usage": True, "request_count": 0}


def _amount(value):
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        raise ValueError("FaithSieve 费用无效") from None
    if not amount.is_finite() or amount < 0:
        raise ValueError("FaithSieve 费用无效")
    return amount


def _money(value):
    return format(value, "f")


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _unstarted(run):
    return run.get("status") == "queued" and not run.get("started_at")


def _has_prior_checkpoints(root, run):
    try:
        with views._directory(root, "faithsieve-work/checkpoints") as directory:
            names = os.listdir(directory)
    except FileNotFoundError:
        return False
    lineage = views._lineage(root, run)
    copied = lineage["keys"] if lineage else set()
    return any((name.startswith("role-") or name == "final-scoring.json")
               and name[:-5] not in copied for name in names)


@contextmanager
def _cost_directory(workspace):
    """费用属于宿主状态，逐级拒绝链接；不创建 Agent 会话或数据库对象。"""
    opened = []
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        root = os.open(Path(workspace), flags)
        opened.append(root)
        try:
            os.mkdir("faithsieve-work", mode=0o700, dir_fd=root)
        except FileExistsError:
            pass
        directory = os.open("faithsieve-work", flags, dir_fd=root)
        opened.append(directory)
        yield directory
    finally:
        for fd in reversed(opened):
            os.close(fd)


def _write_costs(workspace, document):
    payload = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(payload) > _MAX_BYTES:
        raise ValueError("FaithSieve 费用记录超过大小限制")
    temporary = ".cost-" + secrets.token_hex(12)
    with _cost_directory(workspace) as directory:
        fd = None
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            with os.fdopen(fd, "wb") as stream:
                fd = None
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, "cost-events.json", src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass


def _validate_document(document, attempt):
    if (type(document) is not dict or set(document) != {"version", "attempt_id", "history_complete", "events"}
            or type(document["version"]) is not int or document["version"] != 1
            or document["attempt_id"] != attempt or type(document["history_complete"]) is not bool
            or type(document["events"]) is not list or len(document["events"]) > 10000):
        raise ValueError("FaithSieve 费用归属或结构无效")
    identifiers = set()
    for event in document["events"]:
        required = {"id", "invocation_key", "kind", "state", "started_at", "pricing", "usage", "cost_rmb", "estimated"}
        if (type(event) is not dict or set(event) != required or type(event["id"]) is not str
                or not re.fullmatch(r"[a-f0-9]{32}", event["id"]) or event["id"] in identifiers
                or type(event["invocation_key"]) is not str or not _KEY.fullmatch(event["invocation_key"])
                or event["kind"] not in _KINDS or event["state"] not in {"pending", "completed", "failed"}
                or type(event["estimated"]) is not bool or type(event["started_at"]) is not str):
            raise ValueError("FaithSieve 费用事件无效")
        identifiers.add(event["id"])
        if event["cost_rmb"] is not None:
            # 用冻结单价重新核对记录，禁止从请求、模型正文或现配置推测费用。
            try:
                counts, _prices, calculated = calculate_agent_usage_charge(event["usage"], event["pricing"])
            except Exception:
                raise ValueError("FaithSieve 费用 Token 或单价无效") from None
            if event["state"] != "completed" or _amount(event["cost_rmb"]) != calculated or counts != event["usage"]:
                raise ValueError("FaithSieve 费用记录与冻结 Token/价格不一致")
    return document


def _read_document(root_fd, attempt):
    document, info = views._json(root_fd, COST_PATH, limit=_MAX_BYTES, strict=True)
    if info.st_mode & 0o077:
        raise ValueError("FaithSieve 费用文件必须仅供宿主用户读取")
    return _validate_document(document, attempt)


class WorkflowUsageRecorder:
    """只包装真实 chat；checkpoint 命中不会走此入口，也不会新增费用。"""

    def __init__(self, *, run, endpoint, workspace):
        attempt = str(run.get("attempt_id") or "")
        if not _ATTEMPT.fullmatch(attempt):
            raise ValueError("FaithSieve 费用请求编号无效")
        self.attempt, self.workspace = attempt, Path(workspace)
        self.run = dict(run)
        self.endpoint = endpoint
        self.document = None
        self._load()

    def _load(self):
        if self.document is not None:
            return
        with _cost_directory(self.workspace) as directory:
            try:
                fd = os.open("cost-events.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
            except FileNotFoundError:
                # 中途接入或复制历史前缀时，旧请求的价格/缓存 Token 无法补造。
                try:
                    cp = os.open("checkpoints", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                 dir_fd=directory)
                except FileNotFoundError:
                    names = []
                else:
                    try:
                        names = os.listdir(cp)
                    finally:
                        os.close(cp)
                root = os.open(self.workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    lineage = views._lineage(root, self.run)
                finally:
                    os.close(root)
                copied = lineage["keys"] if lineage else set()
                historical = any((name.startswith("role-") or name == "final-scoring.json")
                                 and name[:-5] not in copied for name in names)
                self.document = {"version": 1, "attempt_id": self.attempt,
                                 "history_complete": not historical, "events": []}
                return
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > _MAX_BYTES
                        or info.st_mode & 0o077):
                    raise ValueError("FaithSieve 费用记录不是受限的独立普通文件")
                data = stream.read(_MAX_BYTES + 1)
            if len(data) > _MAX_BYTES:
                raise ValueError("FaithSieve 费用记录过大")
            self.document = _validate_document(json.loads(data, object_pairs_hook=_unique_json_object,
                                                          parse_constant=_reject_json_constant), self.attempt)

    def call(self, invocation_key, kind, callback):
        self._load()
        if not _KEY.fullmatch(invocation_key) or kind not in _KINDS:
            raise ValueError("FaithSieve 费用调用类型无效")
        try:
            pricing = token_pricing_snapshot_from_endpoint(self.endpoint)
            pricing = {key: pricing[key] for key in _PRICE_FIELDS} if pricing else None
        except Exception:
            pricing = None
        event = {"id": secrets.token_hex(16), "invocation_key": invocation_key, "kind": kind,
                 "state": "pending", "started_at": _utc_now(), "pricing": pricing,
                 "usage": None, "cost_rmb": None, "estimated": False}
        self.document["events"].append(event)
        # 先保存调用身份：即使上游断流或宿主退出，也不能把已发请求显示为零费用。
        _write_costs(self.workspace, self.document)
        try:
            response = callback()
        except BaseException:
            event["state"] = "failed"
            self._save_after_response()
            raise
        event["state"] = "completed"
        billing = getattr(getattr(response, "usage", None), "billing_tokens", None)
        if type(billing) is dict:
            event["estimated"] = billing.get("estimated") is True
            event["usage"] = {key: value for key, value in billing.items() if key != "estimated"}
            if pricing is not None:
                try:
                    _counts, _prices, charge = calculate_agent_usage_charge(event["usage"], pricing)
                    event["cost_rmb"] = _money(charge)
                except Exception:
                    event["cost_rmb"] = None
        self._save_after_response()
        return response

    def _save_after_response(self):
        try:
            _write_costs(self.workspace, self.document)
        except Exception:
            # 上游响应已完成时保留 pending 记录供展示缺失，不能因费用写入失败重发模型。
            logger.exception("FaithSieve 费用回传持久化失败", extra={"attempt_id": self.attempt})


def _workflow_cost(run):
    attempt = str(run.get("attempt_id") or "")
    if not _ATTEMPT.fullmatch(attempt):
        return unknown_cost()
    try:
        with views._workspace(run) as root:
            try:
                document = _read_document(root, attempt)
            except FileNotFoundError:
                zero = _unstarted(run) and not _has_prior_checkpoints(root, run)
                return {**unknown_cost(), "complete": zero, "missing_usage": not zero}
    except FileNotFoundError:
        zero = _unstarted(run)
        return {**unknown_cost(), "complete": zero, "missing_usage": not zero}
    except (OSError, ValueError):
        # 缺少工作区是尚未开始的正常情况；损坏/链接不能获得零费用判定。
        return unknown_cost()
    events = document["events"]
    known = [event for event in events if event["cost_rmb"] is not None]
    missing = not document["history_complete"] or len(known) != len(events)
    return {
        "cost_rmb": _money(sum((_amount(event["cost_rmb"]) for event in known), Decimal(0))) if known or not missing else None,
        "currency": "CNY", "complete": not missing,
        "estimated": any(event["estimated"] for event in known),
        "missing_usage": missing, "request_count": len(events),
    }


def _agent_cost_rows(cursor, attempts):
    # 只按数据库中的正式归属计费，缓存来源会话仍属于它实际产生费用的旧 attempt。
    where = "WHERE r.attempt_id IN (" + ",".join("%s" for _ in attempts) + ")"
    params = (AGENT_TRACE_SCHEMA_VERSION, *attempts)
    cursor.execute(
        """SELECT r.attempt_id, a.session_id, a.status AS session_status,
                  t.task_id, t.status AS turn_status,
                  COUNT(l.id) AS request_count, SUM(l.charged_amount) AS cost_rmb,
                  SUM(l.cached_fallback_request_count) AS cached_fallback_request_count,
                  MAX(tr.token_usage_json) AS trace_usage_json
           FROM faithsieve_grading_runs r
           LEFT JOIN submissions s ON s.id=r.submission_id
           JOIN agent_sessions a ON a.task_kind='judge' AND a.judge_kind='faithsieve'
             AND a.attempt_id=r.attempt_id AND a.submission_id=r.submission_id
             AND a.problem_id=r.problem_id AND a.harness=r.harness
             AND a.endpoint_source='global' AND a.endpoint_id=r.endpoint_id
             AND ((r.execution_mode='workflow' AND a.requested_by=r.requested_by)
                  OR ((r.execution_mode='skill' OR r.execution_mode IS NULL)
                      AND (a.requested_by=s.username OR s.id IS NULL)
                      AND a.session_id=r.session_id))
           LEFT JOIN agent_session_turns t ON t.session_id=a.session_id
           LEFT JOIN agent_usage_ledger l ON l.session_id=a.session_id AND l.task_id=t.task_id
           LEFT JOIN agent_trace_sync_state tr ON tr.task_id=t.task_id AND tr.schema_version=%s
           """ + where + " GROUP BY r.attempt_id, a.session_id, a.status, t.task_id, t.status", params,
    )
    return cursor.fetchall() or []


def _agent_usage_missing(row):
    count = int(row.get("request_count") or 0)
    if count == 0 or row.get("pending_usage"):
        return True
    raw = row.get("trace_usage_json")
    if raw:
        try:
            if isinstance(raw, str) and len(raw) > 64 * 1024:
                return True
            usage = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
            if type(usage) is not dict:
                return True
            if usage.get("incremental") is True:
                observed = usage.get("request_count")
                return type(observed) is not int or observed > count
        except (TypeError, ValueError):
            return True
    return False


def _mark_pending_usage(cursor, rows):
    session_tasks = {}
    for row in rows:
        if row.get("task_id"):
            session_tasks.setdefault(row["session_id"], set()).add(row["task_id"])
    if not session_tasks:
        return
    pending = read_pending_usage_events(session_tasks)
    if pending is None:
        for row in rows:
            row["pending_usage"] = True
        return
    if not pending:
        return
    # commit 已成功但 outbox 清理失败时，费用已在上面的正式账本总额中。
    cursor.execute(
        "SELECT session_id, task_id, source, usage_event_id FROM agent_usage_ledger "
        "WHERE (session_id, task_id, source, usage_event_id) IN ("
        + ",".join("(%s,%s,%s,%s)" for _ in pending) + ")",
        tuple(value for event in pending for value in event),
    )
    settled = {tuple(row[name] for name in ("session_id", "task_id", "source", "usage_event_id"))
               for row in cursor.fetchall() or []}
    tasks = {event[1] for event in pending if event not in settled}
    for row in rows:
        if row.get("task_id") in tasks:
            row["pending_usage"] = True


def _merge_run_cost(run, agent_rows):
    is_workflow = run.get("execution_mode") == "workflow"
    pure = _workflow_cost(run) if is_workflow else {**unknown_cost(), "complete": True, "missing_usage": False}
    agent_known = [row for row in agent_rows if row.get("cost_rmb") is not None]
    # 已派发但尚无 usage 的会话不能当成免费；queued 尚未派任务时零成本是可确认的。
    agent_missing = any(_agent_usage_missing(row) for row in agent_rows)
    if not is_workflow and not agent_rows and not _unstarted(run):
        agent_missing = True
    missing = pure["missing_usage"] or agent_missing
    amounts = [pure["cost_rmb"]] if pure["cost_rmb"] is not None else []
    amounts.extend(row["cost_rmb"] for row in agent_known)
    confirmed_zero = _unstarted(run) and not agent_rows and pure["complete"]
    return {
        "cost_rmb": _money(sum((_amount(amount) for amount in amounts), Decimal(0))) if amounts or confirmed_zero else None,
        "currency": "CNY", "complete": not missing,
        "estimated": pure["estimated"] or any(int(row.get("cached_fallback_request_count") or 0) > 0 for row in agent_rows),
        "missing_usage": missing,
        "request_count": pure["request_count"] + sum(int(row.get("request_count") or 0) for row in agent_rows),
    }


def load_run_costs(runs):
    runs = list(runs)
    if not runs:
        return {}
    attempts = [run["attempt_id"] for run in runs if _ATTEMPT.fullmatch(str(run.get("attempt_id") or ""))]
    if len(attempts) != len(runs):
        raise ValueError("FaithSieve 费用请求编号无效")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            rows = _agent_cost_rows(cursor, attempts)
            _mark_pending_usage(cursor, rows)
    finally:
        conn.close()
    return {run["attempt_id"]: _merge_run_cost(run, [row for row in rows if row["attempt_id"] == run["attempt_id"]]) for run in runs}
