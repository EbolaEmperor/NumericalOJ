"""管理员显式授权一次端点重试或同一 Judge 超时续聊；冻结输入始终不变。"""

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import stat
from uuid import uuid4

from .artifacts import ArtifactStore, FaithSieveProtocolError, MAX_ARTIFACT_BYTES, artifact_path
from .checkpoints import CheckpointStore
from .errors import FaithSieveEndpointError, endpoint_error_message
from .prompts import IMAGE_ROLE_NAMES, ROLE_NAMES, TOOL_ROLES
from .runtime_snapshot import read_initial_reasoning_effort


AUTHORIZATION_FILENAME = ".numoj-agent-faithsieve-recovery.json"
_LOCK_FILENAME = ".numoj-agent-faithsieve-recovery.lock"
_MAX_BYTES = 32 * 1024 * 1024
_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_TARGET = re.compile(r"role-[0-9]{6,}-attempt-1\Z")
_NATIVE_FIELDS = {"kind", "session_id", "failed_task_id", "original_timeout_seconds",
                  "continuation_task_id", "continuation_timeout_seconds", "continuation_prompt"}


class FaithSieveRecoveryError(ValueError):
    pass


class FaithSieveRecoveryConflict(FaithSieveRecoveryError):
    pass


class FaithSieveRecoveryDispatchError(FaithSieveRecoveryError):
    pass


def typed_equal(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return (left.keys() == right.keys()
                and all(typed_equal(left[key], right[key]) for key in left))
    if isinstance(left, list):
        return len(left) == len(right) and all(typed_equal(a, b) for a, b in zip(left, right))
    return left == right


def _read(root_fd, name, limit=_MAX_BYTES, *, private=False):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit
                or (private and info.st_mode & 0o077)):
            raise FaithSieveRecoveryError("FaithSieve 恢复材料不是受限的独立普通文件")
        data = stream.read(limit + 1)
        if len(data) > limit or os.fstat(stream.fileno()).st_nlink != 1:
            raise FaithSieveRecoveryError("FaithSieve 恢复材料超过安全边界")
        return data


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FaithSieveRecoveryError("FaithSieve 恢复授权含重复字段")
        result[key] = value
    return result


def _constant(_value):
    raise FaithSieveRecoveryError("FaithSieve 恢复授权不是标准 JSON")


def _native_timeout_target(record):
    request = record.get("request") if type(record) is dict else None
    return (type(request) is dict and record.get("state") == "pending"
            and type(request.get("proof_graph_version")) is int and request["proof_graph_version"] == 3
            and request.get("role") == "local-verifier")


def _validate_native_timeout(value, *, attempt_id, key):
    """只校验持久合同；实际安全终止、原会话及输入由 Judge 只读审计。"""
    from backend.oj_modules.submissions.faithsieve import RUN_TIMEOUT_SECONDS
    session_id = f"fs-{attempt_id}-{key}"
    task_id = f"ft-{attempt_id}-{key}"
    if (type(value) is not dict or set(value) != _NATIVE_FIELDS
            or value.get("kind") != "native_timeout"
            or type(value.get("session_id")) is not str or value["session_id"] != session_id
            or type(value.get("failed_task_id")) is not str or value["failed_task_id"] != task_id
            or type(value.get("continuation_task_id")) is not str or value["continuation_task_id"] != task_id + "-c1"
            or any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value[field])
                   for field in ("session_id", "failed_task_id", "continuation_task_id"))
            or type(value.get("original_timeout_seconds")) is not int or value["original_timeout_seconds"] != 600
            or type(value.get("continuation_timeout_seconds")) is not int
            or not 1 <= value["continuation_timeout_seconds"] <= RUN_TIMEOUT_SECONDS
            or type(value.get("continuation_prompt")) is not str or not value["continuation_prompt"].strip()):
        raise FaithSieveRecoveryError("FaithSieve 超时续聊授权合同无效")
    try:
        if len(value["continuation_prompt"].encode("utf-8")) > MAX_ARTIFACT_BYTES:
            raise UnicodeError
    except UnicodeError:
        raise FaithSieveRecoveryError("FaithSieve 超时续聊指令超限或不是有效文本") from None
    return value


def _inspect_native_timeout(workspace, run, key, record):
    from .judge import inspect_native_timeout
    value = inspect_native_timeout(workspace, run, key, record)
    return _validate_native_timeout(value, attempt_id=run["attempt_id"], key=key)


def _authorized_native_record(permission, key, record):
    """授权目标可以正常完成；完成并不消费第二次续聊机会。"""
    request = record.get("request") if type(record) is dict else None
    if (permission.get("target_key") != key or "native_timeout" not in permission
            or type(request) is not dict or record.get("state") not in {"pending", "completed"}
            or type(request.get("proof_graph_version")) is not int or request["proof_graph_version"] != 3
            or request.get("role") != "local-verifier"
            or not typed_equal(permission["request"], request)
            or (type(record.get("metadata")) is dict and "json_repair" in record["metadata"])):
        raise FaithSieveRecoveryError("FaithSieve 原续聊授权与局部验证完整输入或状态不一致")


def _native_progress_target(workspace, run, permission):
    """只恢复授权后遗漏的已完成 Judge 回读，不授权新的数学请求。"""
    records = CheckpointStore(workspace).records()
    key = permission["target_key"]
    target = records.get(key)
    _authorized_native_record(permission, key, target)
    if target["state"] != "completed":
        raise FaithSieveRecoveryError("FaithSieve 原续聊尚未完成")
    sequences = [record.get("sequence") for record in records.values()]
    if (any(type(value) is not int or value < 1 for value in sequences)
            or len(set(sequences)) != len(sequences)):
        raise FaithSieveRecoveryError("FaithSieve 调用顺序无法确认")
    pending_key, pending = max(records.items(), key=lambda item: item[1]["sequence"])
    if (pending_key == key or not _TARGET.fullmatch(pending_key) or not _native_timeout_target(pending)
            or any(record.get("state") != "completed" for name, record in records.items() if name != pending_key)):
        raise FaithSieveRecoveryError("仅能回读原授权之后尚未收束的完整局部 Judge")
    root_fd = os.open(workspace, _FLAGS)
    try:
        try:
            os.stat("faithsieve_result.json", dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FaithSieveRecoveryError("FaithSieve 已存在数学结果，不能恢复")
    finally:
        os.close(root_fd)
    from .judge import inspect_completed_native
    inspect_completed_native(workspace, run, pending_key, pending)
    return pending_key, pending, records


def _decode(data):
    try:
        payload = json.loads(data.decode("utf-8"), object_pairs_hook=_object, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise FaithSieveRecoveryError("FaithSieve 恢复授权无法安全读取") from None
    fields = {"attempt_id", "actor", "created_at", "target_key", "request", "run_identity"}
    if type(payload) is not dict or set(payload) not in (fields, fields | {"native_timeout"}):
        raise FaithSieveRecoveryError("FaithSieve 恢复授权字段无效")
    if (type(payload["attempt_id"]) is not str or not re.fullmatch(r"[a-f0-9]{32}", payload["attempt_id"])
            or type(payload["actor"]) is not str or not payload["actor"].strip() or len(payload["actor"]) > 50
            or type(payload["target_key"]) is not str or not _TARGET.fullmatch(payload["target_key"])
            or type(payload["request"]) is not dict or type(payload["run_identity"]) is not dict
            or type(payload["created_at"]) is not str):
        raise FaithSieveRecoveryError("FaithSieve 恢复授权内容无效")
    try:
        if datetime.fromisoformat(payload["created_at"]).utcoffset() is None:
            raise ValueError
    except ValueError:
        raise FaithSieveRecoveryError("FaithSieve 恢复授权时间无效") from None
    identity = payload["run_identity"]
    identity_fields = {"attempt_id", "submission_id", "problem_id", "endpoint_id", "harness",
                       "execution_mode", "requested_by", "session_id", "started_at"}
    if (set(identity) != identity_fields or identity.get("attempt_id") != payload["attempt_id"]
            or identity.get("execution_mode") != "workflow"
            or identity.get("session_id") != f"faithsieve-{payload['attempt_id']}"
            or any(type(identity.get(field)) is not int or identity[field] <= 0 for field in ("submission_id", "problem_id", "endpoint_id"))
            or any(type(identity.get(field)) is not str or not identity[field] for field in ("harness", "requested_by", "started_at"))):
        raise FaithSieveRecoveryError("FaithSieve 恢复授权的运行身份无效")
    try:
        datetime.fromisoformat(identity["started_at"])
    except ValueError:
        raise FaithSieveRecoveryError("FaithSieve 恢复授权的原始起点无效") from None
    if "native_timeout" in payload:
        if (type(payload["request"].get("proof_graph_version")) is not int
                or payload["request"]["proof_graph_version"] != 3
                or payload["request"].get("role") != "local-verifier"):
            raise FaithSieveRecoveryError("FaithSieve 超时续聊仅支持图像局部验证")
        _validate_native_timeout(payload["native_timeout"], attempt_id=payload["attempt_id"], key=payload["target_key"])
    return payload


def _run_identity(run):
    identity = {key: run.get(key) for key in (
        "attempt_id", "submission_id", "problem_id", "endpoint_id", "harness", "execution_mode", "requested_by", "session_id",
    )}
    started = run.get("started_at")
    if not isinstance(started, datetime):
        raise FaithSieveRecoveryError("FaithSieve 原运行起点无法确认")
    identity["started_at"] = started.isoformat()
    if (any(type(identity[key]) is not int or identity[key] <= 0 for key in ("submission_id", "problem_id", "endpoint_id"))
            or identity["execution_mode"] != "workflow"
            or type(identity["attempt_id"]) is not str or not re.fullmatch(r"[a-f0-9]{32}", identity["attempt_id"])
            or identity["session_id"] != f"faithsieve-{identity['attempt_id']}"
            or any(type(identity[key]) is not str or not identity[key] for key in ("harness", "requested_by"))):
        raise FaithSieveRecoveryError("FaithSieve 原运行身份无效")
    return identity


def _validate_target_record(key, record):
    request = record.get("request") if type(record) is dict else None
    role = request.get("role") if type(request) is dict else None
    if type(record) is not dict or not _TARGET.fullmatch(key):
        raise FaithSieveRecoveryError("FaithSieve 首次失败调用身份无效")
    metadata = record.get("metadata")
    if type(metadata) is dict and "json_repair" in metadata:
        raise FaithSieveRecoveryError("本阶段已使用一次 JSON 格式修复，不能再重做原任务")
    if _native_timeout_target(record):
        return
    if (record.get("state") != "endpoint_error" or type(role) is not str
            or role not in ROLE_NAMES | IMAGE_ROLE_NAMES or role in TOOL_ROLES):
        raise FaithSieveRecoveryError("仅支持首次纯模型端点失败或图像局部 Judge 超时续聊")
    try:
        endpoint_error_message(metadata.get("endpoint_error") if type(metadata) is dict else None)
    except FaithSieveProtocolError:
        raise FaithSieveRecoveryError("FaithSieve 原失败摘要无法确认") from None


def recovery_target(workspace):
    """取最后一次潜在恢复目标；原生超时还必须经过 Judge 安全终态审计。"""
    records = CheckpointStore(workspace).records()
    if not records:
        raise FaithSieveRecoveryError("FaithSieve 没有可恢复的调用")
    sequences = [record.get("sequence") for record in records.values()]
    if (any(type(value) is not int or value < 1 for value in sequences)
            or len(set(sequences)) != len(sequences)):
        raise FaithSieveRecoveryError("FaithSieve 调用顺序无法确认")
    key, record = max(records.items(), key=lambda item: item[1]["sequence"])
    _validate_target_record(key, record)
    if key.removesuffix("1") + "2" in records:
        raise FaithSieveRecoveryError("仅支持首次纯模型调用的端点失败恢复")
    root_fd = os.open(workspace, _FLAGS)
    try:
        try:
            os.stat("faithsieve_result.json", dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FaithSieveRecoveryError("FaithSieve 已存在数学结果，不能恢复")
    finally:
        os.close(root_fd)
    return key, record, records


@contextmanager
def recovery_lock(workspace):
    root_fd = lock_fd = None
    try:
        root_fd = os.open(workspace, _FLAGS)
        lock_fd = os.open(_LOCK_FILENAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                          0o600, dir_fd=root_fd)
        info = os.fstat(lock_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size:
            raise FaithSieveRecoveryError("FaithSieve 恢复锁无效")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        yield root_fd
    except OSError:
        raise FaithSieveRecoveryError("FaithSieve 恢复材料无法安全访问") from None
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        if root_fd is not None:
            os.close(root_fd)


def prepare_recovery(workspace, run, actor):
    """调用方持有行锁；先追加授权，再提交 queued。失败时不改旧材料。"""
    if type(actor) is not str or not actor.strip() or len(actor) > 50:
        raise FaithSieveRecoveryError("FaithSieve 恢复操作人无效")
    from backend.oj_modules.submissions.faithsieve import RUN_TIMEOUT_SECONDS
    if (run.get("status") != "failed" or run.get("result_json") not in (None, "")
            or type(run.get("elapsed_seconds")) is not int or not 0 <= run["elapsed_seconds"] < RUN_TIMEOUT_SECONDS):
        raise FaithSieveRecoveryError("FaithSieve 恢复状态或整体预算无效")
    identity = _run_identity(run)
    previous = validate_recovery_run(workspace, run)
    if previous and "native_timeout" in previous:
        target, _size = CheckpointStore(workspace)._read_record(previous["target_key"], strict=True)
        _authorized_native_record(previous, previous["target_key"], target)
        if target["state"] == "completed":
            _native_progress_target(workspace, run, previous)
            # 复用原授权，既不重新分配预算，也不增加原生续聊机会。
            return previous
    key, record, _records = recovery_target(workspace)
    payload = {"attempt_id": run["attempt_id"], "actor": actor,
               "created_at": datetime.now(timezone.utc).isoformat(), "target_key": key,
               "request": record["request"], "run_identity": identity}
    if _native_timeout_target(record):
        payload["native_timeout"] = _inspect_native_timeout(workspace, run, key, record)
        if payload["native_timeout"]["continuation_timeout_seconds"] != RUN_TIMEOUT_SECONDS - run["elapsed_seconds"]:
            raise FaithSieveRecoveryError("FaithSieve 续聊预算必须使用原整体时限的剩余秒数")
    with recovery_lock(workspace) as root_fd:
        try:
            previous = _decode(_read(root_fd, AUTHORIZATION_FILENAME, private=True))
        except FileNotFoundError:
            previous = None
        if previous:
            if (previous["target_key"] != key or not typed_equal(previous["request"], record["request"])
                    or not typed_equal(previous["run_identity"], identity)
                    or ("native_timeout" in previous) != ("native_timeout" in payload)):
                raise FaithSieveRecoveryConflict("FaithSieve 已有不同的恢复授权")
            return previous
        data = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(data) > _MAX_BYTES:
            raise FaithSieveRecoveryError("FaithSieve 恢复授权超过大小限制")
        name = f".numoj-agent-faithsieve-recovery-{uuid4().hex}.tmp"
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=root_fd)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.rename(name, AUTHORIZATION_FILENAME, src_dir_fd=root_fd, dst_dir_fd=root_fd)
            os.fsync(root_fd)
        finally:
            try:
                os.unlink(name, dir_fd=root_fd)
            except FileNotFoundError:
                pass
    return payload


def authorize_endpoint_retry(workspace, key, record, request):
    """只有持久显式授权能越过 endpoint_error；不写记录、不解释自然语言。"""
    root_fd = os.open(workspace, _FLAGS)
    try:
        try:
            permission = _decode(_read(root_fd, AUTHORIZATION_FILENAME, private=True))
        except FileNotFoundError:
            return False
    except OSError:
        raise FaithSieveRecoveryError("FaithSieve 恢复授权无法安全读取") from None
    finally:
        os.close(root_fd)
    if permission["target_key"] != key:
        return False
    if "native_timeout" in permission:
        raise FaithSieveRecoveryError("原生 Judge 续聊不能转成纯模型第二次请求")
    _validate_target_record(key, record)
    try:
        original, _size = CheckpointStore(workspace)._read_record(key, strict=True)
    except FaithSieveProtocolError:
        # 已终止失败记录损坏仍是恢复失败，不能覆盖它并进入协议重试。
        raise FaithSieveRecoveryError("FaithSieve 原失败记录无法安全确认") from None
    if (not typed_equal(original, record)
            or not typed_equal(permission["request"], record.get("request"))
            or not typed_equal(permission["request"], request)):
        raise FaithSieveRecoveryError("FaithSieve 恢复请求与原失败调用不一致")
    return True


def read_native_timeout_authorization(workspace, run, key, record, request):
    """Judge 只读获取一次冻结续聊；不改原请求、不派发、不重计预算。"""
    permission = validate_recovery_run(workspace, run)
    if not permission or permission["target_key"] != key or "native_timeout" not in permission:
        return None
    from backend.oj_modules.submissions.faithsieve import RUN_TIMEOUT_SECONDS
    if type(run.get("elapsed_seconds")) is not int or not 0 <= run["elapsed_seconds"] < RUN_TIMEOUT_SECONDS:
        raise FaithSieveRecoveryError("FaithSieve 原整体时限已结束，不能继续 Judge")
    _authorized_native_record(permission, key, record)
    original, _size = CheckpointStore(workspace)._read_record(key, strict=True)
    if (not typed_equal(original, record)
            or not typed_equal(permission["request"], record.get("request"))
            or not typed_equal(permission["request"], request)):
        raise FaithSieveRecoveryError("FaithSieve 续聊与原局部验证完整输入不一致")
    return permission["native_timeout"]


def validate_recovery_run(workspace, run):
    """规范任务入口核对授权绑定的原始 run 身份及起点。"""
    root_fd = os.open(workspace, _FLAGS)
    try:
        try:
            permission = _decode(_read(root_fd, AUTHORIZATION_FILENAME, private=True))
        except FileNotFoundError:
            return
    finally:
        os.close(root_fd)
    if (permission["attempt_id"] != run.get("attempt_id")
            or not typed_equal(permission["run_identity"], _run_identity(run))):
        raise FaithSieveRecoveryError("FaithSieve 恢复授权与原运行身份不一致")
    return permission


def validate_recovery_inputs(workspace, run, *, problem_text, submission_pdf, endpoint, target_key=None):
    """在内存重放严格完成缓存；GET/POST 均不写历史、临时文件或调用模型。"""
    from .budgets import SOURCE_TIMEOUT_SECONDS
    from .workflow import FaithSieveWorkflow, SOURCE
    from .dependency_workflow import DependencyWorkflow
    from .image_workflow import ImageWorkflow, image_render_request
    from backend.oj_modules.submissions.faithsieve import RUN_TIMEOUT_SECONDS

    permission = validate_recovery_run(workspace, run)
    completed_native = False
    records = None
    if permission and "native_timeout" in permission:
        key = permission["target_key"]
        if target_key is not None and target_key != key:
            raise FaithSieveRecoveryError("FaithSieve 恢复调用与原授权不一致")
        target, _size = CheckpointStore(workspace)._read_record(key, strict=True)
        _authorized_native_record(permission, key, target)
        completed_native = target["state"] == "completed"
        if completed_native:
            if type(run.get("elapsed_seconds")) is not int or not 0 <= run["elapsed_seconds"] < RUN_TIMEOUT_SECONDS:
                raise FaithSieveRecoveryError("FaithSieve 原整体时限已结束")
            if target_key is None:
                _pending_key, _pending, records = _native_progress_target(workspace, run, permission)
            else:
                records = CheckpointStore(workspace).records()
                if any(record.get("state") not in {"pending", "completed"} for record in records.values()):
                    raise FaithSieveRecoveryError("FaithSieve 已有新的协议或端点失败，不能复用续聊授权")
        elif target_key is None:
            _inspect_native_timeout(workspace, run, key, target)
    elif target_key is None:
        key, target, _records = recovery_target(workspace)
    else:
        if type(target_key) is not str or not _TARGET.fullmatch(target_key):
            raise FaithSieveRecoveryError("FaithSieve 原恢复调用编号无效")
        key = target_key
        target, _size = CheckpointStore(workspace)._read_record(key, strict=True)
        _validate_target_record(key, target)
    root_fd = os.open(workspace, _FLAGS)
    try:
        original_pdf = _read(root_fd, "submission.pdf", 20 * 1024 * 1024)
    finally:
        os.close(root_fd)
    if original_pdf != submission_pdf:
        raise FaithSieveRecoveryError("FaithSieve 原 PDF 已变化，不能恢复")

    def forbidden(*_args, **_kwargs):
        raise FaithSieveRecoveryError("FaithSieve 恢复前存在未完成步骤，不能自动重做")

    native_target = _native_timeout_target(target)
    if native_target and not permission:
        if target_key is None:
            _inspect_native_timeout(workspace, run, key, target)
        elif read_native_timeout_authorization(workspace, run, key, target, target["request"]) is None:
            raise FaithSieveRecoveryError("FaithSieve 超时续聊尚未显式授权")

    class NativePreviewReady(Exception):
        pass

    visited = set()

    def ready():
        if records is not None and set(records) - visited:
            raise FaithSieveRecoveryError("FaithSieve 历史调用未按原输入完整重放")
        raise NativePreviewReady

    class PreviewStore(CheckpointStore):
        put = forbidden

        def get(self, saved_key, request, **kwargs):
            result = super().get(saved_key, request, **kwargs)
            if (saved_key == key or completed_native) and result and not typed_equal(result["request"], request):
                raise FaithSieveRecoveryError("FaithSieve 恢复请求字段类型或完整输入已变化")
            visited.add(saved_key)
            if completed_native:
                if result is None:
                    if target_key is None:
                        raise FaithSieveRecoveryError("FaithSieve 没有已完成 Judge 可回读")
                    ready()
                if result["state"] == "pending":
                    if not _native_timeout_target(result):
                        raise FaithSieveRecoveryError("FaithSieve 后续调用尚未完整返回，不能自动重做")
                    ready()
            if saved_key == key and native_target and result and result["state"] == "pending":
                raise NativePreviewReady
            return result

    class MemoryArtifacts(ArtifactStore):
        def __init__(self, root):
            self.root, self.visible_paths, self.contents = Path(root), None, {}

        def write(self, relative, content):
            artifact_path(relative)
            if type(content) is not str or len(content.encode("utf-8")) > MAX_ARTIFACT_BYTES:
                raise FaithSieveRecoveryError("FaithSieve 恢复工件无效或超过限制")
            self.contents[relative] = content
            if self.visible_paths is not None:
                self.visible_paths.add(relative)

        def read(self, relative):
            if relative not in self.contents:
                raise FaithSieveRecoveryError("FaithSieve 恢复缺少已完成工件")
            return self.contents[relative]

        def remove(self, relative):
            self.contents.pop(relative, None)
            if self.visible_paths is not None:
                self.visible_paths.discard(relative)

        def bundle(self, paths=(), prefixes=()):
            selected = set(paths) | {name for name in self.contents if any(name.startswith(prefix + "/") for prefix in prefixes)}
            return {name: self.contents[name] for name in sorted(selected) if name in self.contents
                    and (self.visible_paths is None or name in self.visible_paths)}

    class ForbiddenAgent:
        def __getattr__(self, _name):
            return forbidden

    version = target["request"].get("proof_graph_version", 1)
    if type(version) is not int or version not in {1, 2, 3}:
        raise FaithSieveRecoveryError("FaithSieve 原证明图协议版本无效")
    engine = {1: FaithSieveWorkflow, 2: DependencyWorkflow, 3: ImageWorkflow}[version]
    workflow = engine(endpoint=endpoint, verification_agent=ForbiddenAgent(), workspace=workspace,
                                 chat=forbidden, initial_reasoning_effort=read_initial_reasoning_effort(workspace, run["endpoint_id"]),
                                 _artifact_store=MemoryArtifacts(workspace))
    workflow.checkpoints = PreviewStore(workspace)
    workflow._allow_endpoint_recovery = False
    workflow.store.write("problem.md", problem_text)
    if version == 3:
        image_request = image_render_request(problem_text)
        images = workflow.checkpoints.get("image-render", image_request)
        if (not images or images["state"] != "completed" or not typed_equal(images["request"], image_request)):
            raise FaithSieveRecoveryError("FaithSieve 原稿图片未完成或冻结输入已变化，不能恢复")
        workflow.set_images(images.get("response"))
    else:
        legacy_source_request = {"problem_text": problem_text, "pdf_path": "submission.pdf"}
        previous_source_request = {**legacy_source_request, "timeout_seconds": SOURCE_TIMEOUT_SECONDS}
        source_request = {**previous_source_request, **({"proof_graph_version": 2} if version == 2 else {})}
        source = workflow.checkpoints.get("source-extraction", source_request,
                                         completed_legacy_requests=(legacy_source_request, previous_source_request))
        if source and not any(typed_equal(source["request"], original) for original in (
                source_request, legacy_source_request, previous_source_request)):
            raise FaithSieveRecoveryError("FaithSieve 原稿冻结输入字段或类型已变化")
        if source and "timeout_seconds" in source["request"] and type(source["request"]["timeout_seconds"]) is not int:
            raise FaithSieveRecoveryError("FaithSieve 原稿冻结预算字段类型无效")
        extracted = (source or {}).get("response", {})
        if (not source or source.get("state") != "completed" or type(extracted) is not dict or extracted.get("status") != "ok"
                or type(extracted.get("text")) is not str or not extracted["text"].strip()):
            raise FaithSieveRecoveryError("FaithSieve 忠实原稿未完成，不能恢复")
        workflow.store.write(SOURCE, extracted["text"])
    try:
        workflow.run()
    except NativePreviewReady:
        return
    except FaithSieveEndpointError:
        if workflow._role_counter == int(key.split("-")[1]):
            return
    raise FaithSieveRecoveryError("FaithSieve 已完成输入或流程已变化，不能恢复")
