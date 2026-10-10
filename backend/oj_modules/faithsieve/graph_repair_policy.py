"""局部构图返修的宿主策略，与所有冻结数学角色请求分离。"""

from copy import deepcopy
import re

from .artifacts import FaithSieveProtocolError
from .json_repair import strict_equal


GRAPH_REPAIR_POLICY_KEY = "image-graph-repair-policy"
GRAPH_REPAIR_POLICY_VERSION = 1
GRAPH_REPAIR_POLICY_REVISION_LIMIT = 3
_NODE_ID = re.compile(r"N[1-9][0-9]*\Z")


def _error(message):
    return FaithSieveProtocolError("FaithSieve 构图返修策略 " + message)


def _revision_limit(value):
    if type(value) is not int or value != GRAPH_REPAIR_POLICY_REVISION_LIMIT:
        raise _error("版本 1 的每目标返修次数必须为 3")
    return value


def graph_repair_policy_value(*, revision_limit=GRAPH_REPAIR_POLICY_REVISION_LIMIT):
    return {"version": GRAPH_REPAIR_POLICY_VERSION, "mode": "per_node",
            "revision_limit": _revision_limit(revision_limit)}


def graph_repair_policy_request(*, revision_limit=GRAPH_REPAIR_POLICY_REVISION_LIMIT):
    return {"role": GRAPH_REPAIR_POLICY_KEY, **graph_repair_policy_value(revision_limit=revision_limit)}


def validate_graph_repair_policy(value, *, revision_limit=GRAPH_REPAIR_POLICY_REVISION_LIMIT):
    expected = graph_repair_policy_value(revision_limit=revision_limit)
    if not strict_equal(value, expected):
        raise _error("字段、值或类型不符合冻结协议")
    return deepcopy(expected)


def validate_graph_repair_policy_record(record, *, revision_limit=GRAPH_REPAIR_POLICY_REVISION_LIMIT):
    required = {"request", "state", "response"}
    optional = {"sequence", "created_at", "updated_at"}
    if (type(record) is not dict or not required <= set(record) or set(record) - (required | optional)
            or type(record["state"]) is not str or record["state"] != "completed"
            or not strict_equal(record["request"], graph_repair_policy_request(revision_limit=revision_limit))):
        raise _error("宿主 checkpoint 必须是完整且精确的已冻结策略")
    if "sequence" in record and (type(record["sequence"]) is not int or record["sequence"] < 1):
        raise _error("宿主 checkpoint 序号无效")
    for field in ("created_at", "updated_at"):
        if field in record and (type(record[field]) is not str or not record[field]):
            raise _error("宿主 checkpoint 时间字段无效")
    return validate_graph_repair_policy(record["response"], revision_limit=revision_limit)


def select_graph_repair_policy(checkpoints, *, revision_limit=GRAPH_REPAIR_POLICY_REVISION_LIMIT):
    """新运行冻结策略；没有宿主策略的已开始数学前缀继续原全图上限。"""
    _revision_limit(revision_limit)
    try:
        record, _size = checkpoints._read_record(GRAPH_REPAIR_POLICY_KEY, strict=True)
    except FileNotFoundError:
        pass
    else:
        value = validate_graph_repair_policy_record(record, revision_limit=revision_limit)
        # 恢复预检经 get 登记已重放记录；直接读文件不能代替这条规范入口。
        visited = checkpoints.get(GRAPH_REPAIR_POLICY_KEY, graph_repair_policy_request(revision_limit=revision_limit))
        if not strict_equal(visited, record):
            raise _error("宿主 checkpoint 在严格读取与重放登记之间发生变化")
        return value
    try:
        builder, _size = checkpoints._read_record("role-000001-attempt-1", strict=True)
    except FileNotFoundError:
        try:
            records = checkpoints.read_records()
        except FileNotFoundError:
            records = {}
        if set(records) - {"image-render"}:
            raise _error("缺少首个构图请求的历史前缀不完整，不能选择新策略")
        value = graph_repair_policy_value(revision_limit=revision_limit)
        checkpoints.put(GRAPH_REPAIR_POLICY_KEY, graph_repair_policy_request(revision_limit=revision_limit),
                        state="completed", response=value)
        return deepcopy(value)
    if (type(builder) is not dict or type(builder.get("request")) is not dict
            or builder["request"].get("role") != "tree-builder"
            or type(builder.get("state")) is not str
            or builder["state"] not in {"pending", "completed", "protocol_error", "endpoint_error"}):
        raise _error("历史首个构图请求无效，不能选择新策略")
    return None


def _identifier(value):
    if type(value) is not str or not _NODE_ID.fullmatch(value):
        raise _error("局部目标编号无效")
    return value


def _proposition(value):
    if (type(value) is not dict or set(value) != {"id", "kind", "statement"}
            or type(value["kind"]) is not str or value["kind"] not in {"given", "claim", "external"}
            or type(value["statement"]) is not str or not value["statement"].strip()):
        raise _error("局部命题快照字段或类型无效")
    _identifier(value["id"])
    try:
        value["statement"].encode("utf-8")
    except UnicodeError:
        raise _error("局部命题快照不是有效 Unicode") from None


def _context(identifier, value):
    _identifier(identifier)
    if type(value) is not dict or set(value) != {"node", "premises"} or type(value["premises"]) is not list:
        raise _error("局部上下文必须包含完整命题与全部直接前提")
    _proposition(value["node"])
    if value["node"]["id"] != identifier or value["node"]["kind"] != "claim":
        raise _error("局部上下文与待修目标不一致")
    for premise in value["premises"]:
        _proposition(premise)
    ids = [premise["id"] for premise in value["premises"]]
    if ids != sorted(set(ids)) or identifier in ids:
        raise _error("直接前提必须按编号排序、不重复且不含目标本身")
    return deepcopy(value)


class GraphRepairProgress:
    """重放前缀重建计数；同目标的变化不重置次数，不持久化新数学内容。"""

    def __init__(self, policy):
        self._policy = validate_graph_repair_policy(policy)
        self.revision = 0
        self._counts, self._diagnosed_contexts = {}, {}
        self._pending = None
        self._stopped = None

    @property
    def policy(self):
        return deepcopy(self._policy)

    def _stop(self, reason):
        self._stopped = reason
        raise _error(reason)

    def count(self, identifier):
        return self._counts.get(_identifier(identifier), 0)

    def before_repair(self, identifier, context):
        if self._stopped is not None:
            raise _error(self._stopped)
        snapshot = _context(identifier, context)
        if self._pending is not None:
            if self._pending["node_id"] == identifier and strict_equal(self._pending["context"], snapshot):
                return self._pending["revision"]
            raise _error("未完成返修的目标或完整上下文已改变")
        history = self._diagnosed_contexts.get(identifier, [])
        if any(strict_equal(previous, snapshot) for previous in history):
            self._stop("同一局部目标的完整上下文再次出现构图缺陷，不能重复无进展返修")
        if self.count(identifier) >= self._policy["revision_limit"]:
            self._stop("同一局部目标经 3 次返修仍不能忠实表达原稿")
        self.revision += 1
        self._counts[identifier] = self.count(identifier) + 1
        self._diagnosed_contexts.setdefault(identifier, []).append(deepcopy(snapshot))
        self._pending = {"node_id": identifier, "context": snapshot, "revision": self.revision}
        return self.revision

    def after_repair(self, identifier, context):
        if self._stopped is not None:
            raise _error(self._stopped)
        snapshot = _context(identifier, context)
        if self._pending is None or self._pending["node_id"] != identifier:
            raise _error("返修完成与待修局部目标不一致")
        if any(strict_equal(previous, snapshot) for previous in self._diagnosed_contexts[identifier]):
            self._stop("修订没有改变局部完整命题或直接前提，或回到了此前已有缺陷的上下文")
        self._pending = None


__all__ = ["GRAPH_REPAIR_POLICY_KEY", "GRAPH_REPAIR_POLICY_VERSION", "GRAPH_REPAIR_POLICY_REVISION_LIMIT",
           "graph_repair_policy_request", "graph_repair_policy_value", "validate_graph_repair_policy",
           "validate_graph_repair_policy_record", "select_graph_repair_policy", "GraphRepairProgress"]
