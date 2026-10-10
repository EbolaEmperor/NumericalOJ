"""从持久检查点展示 FaithSieve；只读，不初始化 workspace 或派发任务。"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import PurePosixPath
import re
import stat

from backend.oj_modules.agents import workspace as workspace_store
from backend.oj_modules.agents.sessions import get_agent_session
from backend.oj_modules.submissions.faithsieve import get_run

from .artifacts import (MAX_ARTIFACT_BYTES, FaithSieveProtocolError,
                        _reject_json_constant, _unique_json_object)
from .errors import endpoint_error_message
from .proof_tree import TREE_PATH, parse_proof_tree, step_ids
from .proof_dag import parse_proof_dag
from .node_verification import NODE_VERIFICATION_PATH, validate_node_verification_summary
from .local_diagnostics import validate_graph_diagnostics
from .node_selection import (NODE_SELECTION_PATH, NODE_SELECTION_FALLBACK_REASON,
                             default_node_selection_order, validate_node_selection_fallback)
from .json_repair import strict_equal


_MAX_RECORD_BYTES = 32 * 1024 * 1024
_MAX_SNAPSHOT_BYTES = 128 * 1024 * 1024
_MAX_RECORDS = 512
_KEY = re.compile(r"(?:image-render|source-extraction|final-scoring|role-[0-9]{6,}-attempt-[12]|compile-[0-9]{6,})\Z")
_ATTEMPT = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
_EDGE = r"E[1-9][0-9]*"
_NODE = r"N[1-9][0-9]*"
_UNIT = rf"(?:{_EDGE}|{_NODE})"
_OBLIGATION = rf"{_UNIT}-O[1-9][0-9]*"
_BRANCH = r"(?:original|negation|counterexample)"
_LABELS = {
    "image-render": "渲染原稿图片", "local-verifier": "验证局部命题",
    "verification-auditor": "审核局部验证",
    "node-selector": "选择验证顺序",
    "source-extraction": "看图核对并整理学生原稿", "decomposer": "忠实拆分证明",
    "decomposition-auditor": "独立审计证明拆分", "tree-builder": "建立证明状态树",
    "tree-auditor": "独立审计证明状态树", "suspicion-scanner": "扫描证明风险",
    "local-reviewer": "局部复核证明步骤", "obligation-builder": "生成数学义务",
    "check-object-generator": "忠实转换检查对象", "numeric-evaluator": "执行数值验证",
    "statement-formalizer": "形式化数学命题", "semantic-checker": "独立核对形式化语义",
    "proof-searcher": "搜索 Lean 证明", "evidence-mapper": "映射验证证据",
    "prefix-auditor": "复查首错前缀", "final-synthesizer": "综合数学结论",
    "consistency-auditor": "独立审计最终证据链", "scoring": "按原量表评分",
    "lean-compiler": "独立编译 Lean 文件",
}
_JUDGE_ROLES = {"local-verifier", "source-extraction", "numeric-evaluator", "statement-formalizer", "proof-searcher"}
_ROOT_ARTIFACTS = {
    "problem.md", "faithsieve_result.json", "faithsieve-work/source/submission.md",
    "faithsieve-work/source/extraction.txt", "faithsieve-work/source/extraction.json",
    "faithsieve-work/steps.md", TREE_PATH, "faithsieve-work/tree.md", "faithsieve-work/scan.md",
    "faithsieve-work/evidence-map.md", "faithsieve-work/prefix-review.md", "faithsieve-work/final.md",
    "faithsieve-work/review/decomposition.md", "faithsieve-work/review/tree.md",
    "faithsieve-work/review/final.md", NODE_VERIFICATION_PATH, NODE_SELECTION_PATH,
}
_RESULT_NAME = (
    r"(?:decomposer|decomposition-auditor|tree-builder|tree-auditor|suspicion-scanner|"
    r"node-selector|evidence-mapper|prefix-auditor|final-synthesizer|consistency-auditor|"
    rf"{_UNIT}-(?:local-verifier|local-reviewer|obligation-builder)|{_NODE}-verification-auditor|"
    rf"{_OBLIGATION}-(?:check-object-generator|numeric-evaluator)|"
    rf"{_OBLIGATION}-{_BRANCH}-(?:statement-formalizer|semantic-checker|proof-searcher))"
)
_ARTIFACT_PATTERNS = (
    rf"faithsieve-work/verification/{_NODE}\.md",
    rf"faithsieve-work/review/{_UNIT}\.md",
    rf"faithsieve-work/review/{_NODE}-verification\.md",
    rf"faithsieve-work/obligations/{_UNIT}/(?:index|{_OBLIGATION})\.md",
    rf"faithsieve-work/formal/{_OBLIGATION}-(?:check|numeric)\.md",
    rf"faithsieve-work/formal/{_OBLIGATION}-verification\.json",
    rf"faithsieve-work/formal/{_OBLIGATION}-{_BRANCH}-(?:statement|proof)\.lean",
    rf"faithsieve-work/formal/{_OBLIGATION}-{_BRANCH}-(?:diagnostics|proof-diagnostics)\.txt",
    rf"faithsieve-work/formal/{_OBLIGATION}-{_BRANCH}-semantics\.md",
    rf"faithsieve-work/results/{_RESULT_NAME}\.json(?:\.expressions\.json)?",
)
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
_LINEAGE_FILENAME = ".numoj-agent-faithsieve-debug-lineage.json"
_LINEAGE_FIELDS = {"source_attempt", "destination_attempt", "created_at", "source_prefix_keys",
                   "boundary_key", "reason", "native_origins", "database_preflight"}
_LINEAGE_REQUIRED = {"source_attempt", "destination_attempt", "source_prefix_keys", "boundary_key", "native_origins"}
_LINEAGE_LIMIT = 1024 * 1024
_LINEAGE_ATTEMPT = re.compile(r"[a-f0-9]{32}\Z")
_ROLE_KEY = re.compile(r"role-[0-9]{6,}-attempt-[12]\Z")


class FaithSieveViewError(ValueError):
    """已保存的展示材料不满足只读安全边界。"""


class FaithSieveArtifactNotFoundError(FileNotFoundError):
    """工件不存在或未在允许展示的数学产物中。"""


def _identity(run):
    attempt = str(run.get("attempt_id") or "")
    if not _ATTEMPT.fullmatch(attempt):
        raise FaithSieveViewError("FaithSieve 请求编号无效")
    session_id = f"faithsieve-{attempt}"
    if run.get("session_id") and run["session_id"] != session_id:
        raise FaithSieveViewError("FaithSieve 工作区身份不一致")
    return attempt, session_id


def _parts(path):
    if not isinstance(path, str) or not path or "\\" in path or "\x00" in path:
        raise FaithSieveViewError("FaithSieve 文件路径无效")
    parts = path.split("/")
    if any(not part or part in {".", ".."} or part.startswith(".") for part in parts):
        raise FaithSieveViewError("FaithSieve 文件路径无效")
    return tuple(parts)


def _artifact_allowed(path):
    try:
        _parts(path)
    except FaithSieveViewError:
        return False
    return path in _ROOT_ARTIFACTS or any(re.fullmatch(pattern, path) for pattern in _ARTIFACT_PATTERNS)


@contextmanager
def _workspace(run):
    """逐级 O_NOFOLLOW 固定目录；不能调用会 mkdir/chmod 的 Agent 读取入口。"""
    _attempt, session_id = _identity(run)
    root = workspace_store._workspace_root()
    opened = []
    try:
        fd = os.open(root.anchor, _DIR_FLAGS)
        opened.append(fd)
        for part in (*root.parts[1:], "sessions", session_id, "workspace"):
            fd = os.open(part, _DIR_FLAGS, dir_fd=fd)
            opened.append(fd)
        yield fd
    except FileNotFoundError:
        raise
    except OSError:
        raise FaithSieveViewError("FaithSieve 工作区无法安全读取") from None
    finally:
        for fd in reversed(opened):
            os.close(fd)


@contextmanager
def _directory(root_fd, path):
    opened = []
    try:
        fd = root_fd
        for part in _parts(path):
            fd = os.open(part, _DIR_FLAGS, dir_fd=fd)
            opened.append(fd)
        yield fd
    except FileNotFoundError:
        raise
    except OSError:
        raise FaithSieveViewError("FaithSieve 文件目录无法安全读取") from None
    finally:
        for fd in reversed(opened):
            os.close(fd)


def _read(root_fd, path, *, limit=MAX_ARTIFACT_BYTES):
    parts = _parts(path)
    @contextmanager
    def parent():
        if len(parts) == 1:
            yield root_fd
        else:
            with _directory(root_fd, "/".join(parts[:-1])) as fd:
                yield fd
    fd = None
    try:
        with parent() as parent_fd:
            fd = os.open(parts[-1], _FILE_FLAGS, dir_fd=parent_fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise FaithSieveViewError("FaithSieve 文件不是受限的独立普通文件")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            data = stream.read(limit + 1)
            if os.fstat(stream.fileno()).st_nlink != 1 or len(data) > limit:
                raise FaithSieveViewError("FaithSieve 文件在读取期间超出安全边界")
        return data.decode("utf-8"), info
    except FileNotFoundError:
        raise
    except (OSError, UnicodeError):
        raise FaithSieveViewError("FaithSieve 文件无法安全读取") from None
    finally:
        if fd is not None:
            os.close(fd)


def _json(root_fd, path, *, limit=_MAX_RECORD_BYTES, strict=False):
    content, info = _read(root_fd, path, limit=limit)
    try:
        value = json.loads(content, **({"object_pairs_hook": _unique_json_object,
                                       "parse_constant": _reject_json_constant} if strict else {}))
    except (ValueError, RecursionError):
        raise FaithSieveViewError("FaithSieve 展示记录格式无效") from None
    if not isinstance(value, dict):
        raise FaithSieveViewError("FaithSieve 展示记录格式无效")
    return value, info


def _records(root_fd, summary=None):
    summary = summary if summary is not None else {}
    summary.update(stage_count=0, shown_stage_count=0, truncated=False)
    try:
        with _directory(root_fd, "faithsieve-work/checkpoints") as fd:
            names = [name for name in os.listdir(fd) if name.endswith(".json") and _KEY.fullmatch(name[:-5])]
            entries = [(name, os.stat(name, dir_fd=fd, follow_symlinks=False)) for name in names]
    except FileNotFoundError:
        return []
    summary["stage_count"] = len(entries)
    entries.sort(key=lambda entry: (entry[1].st_mtime_ns, entry[0]))
    records, total = [], 0
    sequences = set()
    for name, listed_info in entries:
        if len(records) >= _MAX_RECORDS or total + listed_info.st_size > _MAX_SNAPSHOT_BYTES:
            summary["truncated"] = True
            break
        record, info = _json(root_fd, f"faithsieve-work/checkpoints/{name}")
        total += info.st_size
        if total > _MAX_SNAPSHOT_BYTES:
            summary["truncated"] = True
            break
        if record.get("state") not in {"pending", "completed", "protocol_error", "endpoint_error"} or not isinstance(record.get("request"), dict):
            raise FaithSieveViewError("FaithSieve 步骤状态无效")
        sequence = record.get("sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
            sequence = None
        elif sequence in sequences:
            raise FaithSieveViewError("FaithSieve 步骤顺序重复")
        else:
            sequences.add(sequence)
        records.append((name[:-5], record, info, sequence))
    # 新记录使用首次调用编号；旧记录只能按文件更新时间恢复近似顺序。
    records.sort(key=lambda item: (item[3] is not None, item[3] or item[2].st_mtime_ns, item[0]))
    summary["shown_stage_count"] = len(records)
    return records


def _text(value, limit=64 * 1024):
    return value[:limit] if isinstance(value, str) else ""


def _timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value).isoformat()
    except ValueError:
        return None


def _artifact_metadata(path, content, *, stage_key=None):
    suffix = PurePosixPath(path).suffix
    result = {"path": path, "name": PurePosixPath(path).name,
              "language": {".lean": "lean", ".json": "json", ".md": "markdown"}.get(suffix, "text"),
              "size": len(content.encode("utf-8"))}
    if stage_key is not None:
        result["stage_key"] = stage_key
    return result


def proof_tree_projection(path, content, *, steps_markdown=""):
    """依赖图与历史状态树分别校验，不能把历史树推断成数学依赖。"""
    if path == TREE_PATH:
        try:
            expected = step_ids(steps_markdown) if steps_markdown else None
            raw = json.loads(content)
            if isinstance(raw, dict) and type(raw.get("schema_version")) is int and raw["schema_version"] in {2, 3}:
                return parse_proof_dag(content, expected_steps=expected if raw["schema_version"] == 2 else None), "dependency_dag"
            return parse_proof_tree(content, expected_steps=expected), "json"
        except ValueError:
            return None, None
    if path == "faithsieve-work/tree.md":
        from .legacy_proof_tree import parse_legacy_proof_tree
        tree = parse_legacy_proof_tree(content, steps_markdown)
        return (tree, "legacy_markdown") if tree is not None else (None, None)
    return None, None


def node_verification_projection(root_fd, dag):
    """只投影与完整图一致、可重算的宿主结论，避免修订串用同名节点。"""
    try:
        saved, _info = _json(root_fd, NODE_VERIFICATION_PATH, limit=MAX_ARTIFACT_BYTES)
    except FileNotFoundError:
        return None
    try:
        return validate_node_verification_summary(saved, dag)["nodes"]
    except (ValueError, KeyError, TypeError):
        return None


def _node_selection_fallback(record):
    """只展示与冻结图精确匹配的代码回退，不公开模型失败输入。"""
    request, metadata = record.get("request"), record.get("metadata")
    if (record.get("state") not in {"completed", "protocol_error", "endpoint_error"}
            or type(request) is not dict or request.get("role") != "node-selector"
            or type(request.get("proof_graph_version")) is not int or request["proof_graph_version"] != 3
            or type(request.get("node_selection_version")) is not int or request["node_selection_version"] != 1
            or type(metadata) is not dict or "node_selection_fallback" not in metadata):
        return None
    files = request.get("files")
    if type(files) is not dict or type(files.get(TREE_PATH)) is not str:
        return None
    try:
        dag = parse_proof_dag(files[TREE_PATH])
        if dag["schema_version"] != 3:
            return None
        return validate_node_selection_fallback(metadata["node_selection_fallback"],
                                                expected_node_ids=default_node_selection_order(dag))
    except (ValueError, KeyError, TypeError):
        return None


def _outputs(key, record):
    """只提取已完成响应中的数学产物，绝不将 request/files 当作工件。"""
    fallback = _node_selection_fallback(record)
    if fallback is not None:
        return {NODE_SELECTION_PATH: json.dumps({"node_ids": fallback["node_ids"]}, ensure_ascii=False, indent=2)}
    if record["state"] != "completed" or not isinstance(record.get("response"), dict):
        return {}
    response, request = record["response"], record["request"]
    outputs = {}
    artifacts = response.get("artifacts")
    if isinstance(artifacts, dict):
        for path, content in artifacts.items():
            if _artifact_allowed(path) and isinstance(content, str) and len(content.encode("utf-8")) <= MAX_ARTIFACT_BYTES:
                outputs[path] = content
    if key == "source-extraction":
        if isinstance(response.get("text"), str):
            outputs["faithsieve-work/source/submission.md"] = response["text"]
        outputs["faithsieve-work/source/extraction.txt"] = _text(response.get("report"))
    elif key == "final-scoring":
        if set(response) == {"verdict", "score", "comment"}:
            outputs["faithsieve_result.json"] = json.dumps(response, ensure_ascii=False, indent=2)
    elif key.startswith("compile-"):
        metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
        path = metadata.get("diagnostics_path")
        if not path:
            statement = request.get("statement_path", "")
            if isinstance(statement, str):
                path = re.sub(r"-(statement|proof)\.lean$", lambda match: "-proof-diagnostics.txt" if match[1] == "proof" else "-diagnostics.txt", statement)
        if _artifact_allowed(path) and isinstance(response.get("diagnostics"), str):
            outputs[path] = response["diagnostics"]
    else:
        path, result = request.get("expected_result_path"), response.get("result")
        if _artifact_allowed(path) and isinstance(result, dict):
            public_result = {name: result[name] for name in ("status", "artifact", "report", "focus_unit", "candidate_units", "verdict") if name in result}
            if (request.get("role") in {"local-verifier", "verification-auditor"}
                    and type(request.get("local_diagnostic_version")) is int
                    and request["local_diagnostic_version"] == 1 and "diagnostics" in result):
                try:
                    public_result["diagnostics"] = validate_graph_diagnostics(result.get("status"), result["diagnostics"])
                except FaithSieveProtocolError:
                    # 不把未通过协议的额外字段公开为可信构图诊断。
                    pass
            outputs[path] = json.dumps(public_result, ensure_ascii=False, indent=2)
    return {path: content for path, content in outputs.items() if len(content.encode("utf-8")) <= MAX_ARTIFACT_BYTES}


def _parameters(request):
    values = request.get("parameters")
    values = values if isinstance(values, dict) else {}
    result = {}
    for name, pattern in (("edge_id", _EDGE), ("node_id", _NODE), ("obligation_id", _OBLIGATION), ("branch", _BRANCH)):
        if isinstance(values.get(name), str) and re.fullmatch(pattern, values[name]):
            result[name] = values[name]
    obligation = result.get("obligation_id")
    if obligation and obligation.startswith("N"):
        node_id = obligation.split("-O", 1)[0]
        if result.get("node_id", node_id) != node_id:
            raise FaithSieveViewError("FaithSieve 义务与节点身份不一致")
        result["node_id"] = node_id
    if not result and isinstance(request.get("statement_path"), str):
        match = re.search(rf"/({_OBLIGATION})-({_BRANCH})-(statement|proof)\.lean$", request["statement_path"])
        if match:
            unit = match[1].split("-", 1)[0]
            result = {"node_id" if unit.startswith("N") else "edge_id": unit,
                      "obligation_id": match[1], "branch": match[2], "target": match[3]}
    return result


def _lineage(root_fd, run):
    """只读内部来源合同；预检材料不参与授权，也不成为公开工件。"""
    fd = None
    try:
        fd = os.open(_LINEAGE_FILENAME, _FILE_FLAGS, dir_fd=root_fd)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_size > _LINEAGE_LIMIT or info.st_mode & 0o077):
            raise FaithSieveViewError("FaithSieve 缓存来源文件不满足只读安全边界")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            data = stream.read(_LINEAGE_LIMIT + 1)
            if len(data) > _LINEAGE_LIMIT or os.fstat(stream.fileno()).st_nlink != 1:
                raise FaithSieveViewError("FaithSieve 缓存来源文件超出安全边界")
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_json_object,
                           parse_constant=_reject_json_constant)
    except FileNotFoundError:
        return None
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise FaithSieveViewError("FaithSieve 缓存来源文件无法安全读取") from None
    finally:
        if fd is not None:
            os.close(fd)
    attempt, _sid = _identity(run)
    if (type(value) is not dict or not _LINEAGE_REQUIRED <= set(value) or set(value) - _LINEAGE_FIELDS
            or type(value["source_attempt"]) is not str or not _LINEAGE_ATTEMPT.fullmatch(value["source_attempt"])
            or value["source_attempt"] == attempt or value["destination_attempt"] != attempt
            or type(value["destination_attempt"]) is not str or not _LINEAGE_ATTEMPT.fullmatch(attempt)
            or type(value["source_prefix_keys"]) is not list or not 1 <= len(value["source_prefix_keys"]) <= _MAX_RECORDS
            or any(type(item) is not str or not _KEY.fullmatch(item) for item in value["source_prefix_keys"])
            or len(set(value["source_prefix_keys"])) != len(value["source_prefix_keys"])
            or type(value["boundary_key"]) is not str or not _ROLE_KEY.fullmatch(value["boundary_key"])
            or value["boundary_key"] in value["source_prefix_keys"]
            or type(value["native_origins"]) is not list or len(value["native_origins"]) > _MAX_RECORDS):
        raise FaithSieveViewError("FaithSieve 缓存来源合同无效")
    origins = {}
    for origin in value["native_origins"]:
        source_attempt = origin.get("source_attempt", value["source_attempt"]) if type(origin) is dict else None
        if (type(origin) is not dict
                or set(origin) not in ({"key", "origin_session", "origin_task", "status"},
                                      {"key", "origin_session", "origin_task", "status", "source_attempt"})
                or type(source_attempt) is not str or not _LINEAGE_ATTEMPT.fullmatch(source_attempt)
                or source_attempt == attempt
                or type(origin["key"]) is not str or not _ROLE_KEY.fullmatch(origin["key"])
                or origin["key"] not in value["source_prefix_keys"] or origin["key"] in origins
                or type(origin["origin_session"]) is not str or type(origin["origin_task"]) is not str
                or origin["origin_session"] != f"fs-{source_attempt}-{origin['key']}"
                or origin["origin_task"] not in {f"ft-{source_attempt}-{origin['key']}",
                                                 f"ft-{source_attempt}-{origin['key']}-c1"}
                or type(origin["status"]) is not str
                or origin["status"] not in {"passed", "refuted", "inconclusive", "graph_defect"}):
            raise FaithSieveViewError("FaithSieve 缓存 Judge 来源身份无效")
        origins[origin["key"]] = {**origin, "source_attempt": source_attempt}
    return {"source_attempt": value["source_attempt"], "keys": set(value["source_prefix_keys"]), "origins": origins}


def _cached_judge(root_fd, run, key, role, record):
    """完整缓存经来源与原会话双重核对后，只公开既有 Judge 链接。"""
    if (type(record) is not dict or record.get("state") != "completed" or role != "local-verifier"
            or type(record.get("request")) is not dict
            or type(record["request"].get("proof_graph_version")) is not int
            or record["request"]["proof_graph_version"] != 3):
        return {}
    lineage = _lineage(root_fd, run)
    if lineage is None or key not in lineage["keys"] or key not in lineage["origins"]:
        return {}
    origin = lineage["origins"][key]
    source_attempt = origin["source_attempt"]
    source = get_run(source_attempt)
    if source is None:
        return {}
    if (type(source) is not dict or source.get("attempt_id") != source_attempt
            or source.get("execution_mode") != "workflow" or run.get("execution_mode") != "workflow"
            or source.get("status") not in {"completed", "failed", "inconclusive"}
            or any(type(run.get(name)) is not int or run[name] <= 0
                   for name in ("problem_id", "submission_id"))
            or type(run.get("requested_by")) is not str or not run["requested_by"].strip()
            or any(not strict_equal(source.get(name), run.get(name))
                   for name in ("problem_id", "submission_id", "requested_by"))):
        raise FaithSieveViewError("FaithSieve 缓存 Judge 运行归属不一致")
    runtime = run.get("runtime") if type(run.get("runtime")) is dict else run
    if (type(runtime.get("harness")) is not str or not runtime["harness"]
            or type(runtime.get("endpoint_id")) is not int or runtime["endpoint_id"] <= 0
            or any(not strict_equal(source.get(name), runtime.get(name)) for name in ("harness", "endpoint_id"))):
        raise FaithSieveViewError("FaithSieve 缓存 Judge 运行配置不一致")
    try:
        with _workspace(source) as source_fd:
            source_record, _info = _json(source_fd, f"faithsieve-work/checkpoints/{key}.json", strict=True)
            destination_record, _info = _json(root_fd, f"faithsieve-work/checkpoints/{key}.json", strict=True)
            if (source_record.get("state") != "completed" or destination_record.get("state") != "completed"
                    or type(source_record.get("response")) is not dict
                    or any(not strict_equal(source_record.get(name), record.get(name))
                           or not strict_equal(destination_record.get(name), record.get(name))
                           for name in ("request", "response"))):
                raise FaithSieveViewError("FaithSieve 缓存 Judge 完整输入或结果与来源不一致")
            execution = source_record["response"].get("execution")
            result = source_record["response"].get("result")
            if (type(execution) is not dict or execution.get("provider") != "numoj-agent-judge"
                    or execution.get("session_id") != origin["origin_session"]
                    or execution.get("task_id") != origin["origin_task"]
                    or type(result) is not dict or result.get("status") != origin["status"]):
                raise FaithSieveViewError("FaithSieve 缓存 Judge 执行记录与来源身份不一致")
            # 每条来源必须直连实际执行的原 manifest，不能再沿来源的 lineage 寻找会话。
            judge = _judge(source_fd, source, key, role, allow_cached=False)
    except FileNotFoundError:
        return {}
    if not judge:
        return {}
    if (judge["session_id"] != origin["origin_session"] or judge["task_id"] != origin["origin_task"]
            or judge.get("judge_status") != "Completed"):
        raise FaithSieveViewError("FaithSieve 缓存 Judge 原会话归属或完成状态不一致")
    return judge


def _judge(root_fd, run, key, role, *, record=None, allow_cached=True):
    try:
        saved, _info = _json(root_fd, f"faithsieve-work/judge-invocations/{key}.json", limit=8 * 1024 * 1024)
    except FileNotFoundError:
        return _cached_judge(root_fd, run, key, role, record) if allow_cached else {}
    attempt, _sid = _identity(run)
    expected_sid, expected_tid = f"fs-{attempt}-{key}", f"ft-{attempt}-{key}"
    if saved.get("session_id") != expected_sid or saved.get("task_id") != expected_tid or saved.get("role") != ("source-extractor" if role == "source-extraction" else role):
        raise FaithSieveViewError("FaithSieve Judge 记录身份不一致")
    try:
        continuation, _info = _json(root_fd, f"faithsieve-work/judge-invocations/{key}/continuation.json", limit=8 * 1024 * 1024)
    except FileNotFoundError:
        continuation = None
    if continuation is not None:
        from .judge import FaithSieveJudgeError, validate_native_continuation
        if saved.get("proof_graph_version") != 3 or role != "local-verifier":
            raise FaithSieveViewError("FaithSieve Judge 续跑协议不一致")
        try:
            validate_native_continuation(continuation, saved)
        except (FaithSieveJudgeError, KeyError, TypeError) as exc:
            raise FaithSieveViewError("FaithSieve Judge 续跑身份不一致") from exc
        expected_tid = continuation["continuation_task_id"]
    session = get_agent_session(expected_sid)
    if not session:
        return {}
    expected = {"task_kind": "judge", "judge_kind": "faithsieve", "attempt_id": attempt,
                "session_id": expected_sid, "current_task_id": expected_tid,
                "submission_id": run.get("submission_id"), "requested_by": run.get("requested_by")}
    if run.get("problem_id") is not None:
        expected["problem_id"] = run["problem_id"]
    runtime = run.get("runtime") if isinstance(run.get("runtime"), dict) else run
    for name in ("harness", "endpoint_id"):
        if runtime.get(name) is not None:
            expected[name] = runtime[name]
    if any(str(session.get(name)) != str(value) for name, value in expected.items()):
        raise FaithSieveViewError("FaithSieve Judge 会话归属不一致")
    return {"session_id": expected_sid, "task_id": expected_tid, "judge_status": _text(session.get("status"), 64)}


def _preprocessing(root_fd):
    try:
        saved, _info = _json(root_fd, "faithsieve-work/judge-invocations/source-extraction/rendered/extraction.json", limit=MAX_ARTIFACT_BYTES)
    except FileNotFoundError:
        return {}
    pages = []
    for page in saved.get("pages", []) if isinstance(saved.get("pages"), list) else []:
        if isinstance(page, dict) and isinstance(page.get("page"), int) and not isinstance(page["page"], bool):
            pages.append({"page": page["page"], "rendered": page.get("rendered") is True})
    code = saved.get("exit_code")
    return {"label": "PDF 逐页图像渲染", "kind": "code", "state": "completed",
            "report": f"已渲染 {sum(page['rendered'] for page in pages)} / {len(pages)} 页原稿图像。", "pages": pages,
            "exit_code": code if isinstance(code, int) and not isinstance(code, bool) else None}


def _environment(root_fd):
    try:
        saved, _info = _json(root_fd, "faithsieve-work/tool-preflight.json", limit=MAX_ARTIFACT_BYTES)
    except FileNotFoundError:
        return {}
    result = saved.get("result") if isinstance(saved.get("result"), dict) else {}
    ready = result.get("ready") is True
    code = result.get("exit_code")
    return {"label": "预装数学与原稿工具环境检查", "kind": "code", "state": "completed",
            "status": "passed" if ready else "failed", "ready": ready,
            "report": _text(result.get("stdout")) + _text(result.get("stderr")),
            "exit_code": code if isinstance(code, int) and not isinstance(code, bool) else None}


def _input_files(request):
    if isinstance(request.get("files"), dict):
        return request["files"]
    # 最终评分沿用一次 LLM 的 messages 协议；只在服务内解析输入找依赖。
    for message in reversed(request.get("messages", []) if isinstance(request.get("messages"), list) else []):
        if not isinstance(message, dict) or message.get("role") != "user" or not isinstance(message.get("content"), str):
            continue
        try:
            content = json.loads(message["content"])
        except ValueError:
            continue
        if isinstance(content, dict) and isinstance(content.get("input_files"), dict):
            return content["input_files"]
    return {}


def _role_scope(role, parameters):
    if role in {"local-reviewer", "obligation-builder"}:
        return parameters.get("node_id") or parameters.get("edge_id") or str(parameters.get("obligation_id") or "").split("-O", 1)[0]
    if role in {"check-object-generator", "numeric-evaluator"}:
        return parameters.get("obligation_id")
    if role in {"statement-formalizer", "semantic-checker", "proof-searcher"}:
        return (parameters.get("obligation_id"), parameters.get("branch"))
    return None


def _dag(records, stages, warnings):
    """按原文和真实放行门恢复依赖，再约简冗余边；绝不按序号机械串链。"""
    producers, latest_roles, latest_compiles, branch_terminals, ancestors = {}, {}, {}, {}, {}
    previous, edges = {}, []
    for (key, record, _info, _sequence), stage in zip(records, stages):
        request, role = record["request"], stage["role"]
        parameters = stage["parameters"]
        inputs = _input_files(request)
        parents = set()
        for path, content in inputs.items():
            if not isinstance(path, str) or not isinstance(content, str):
                continue
            for producer, original in reversed(producers.get(path, [])):
                if content == original:
                    parents.add(producer)
                    break
        metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
        explicit = metadata.get("dependency_keys")
        if isinstance(explicit, list):
            parents.update(parent for parent in explicit if isinstance(parent, str) and parent in previous)
            if any(isinstance(parent, str) and parent and parent not in previous for parent in explicit):
                message = "部分依赖记录无法确认或未载入，图中已省略这些连线。"
                if message not in warnings:
                    warnings.append(message)
        else:
            # 老记录没有门控元数据，按原控制代码和同一作用域的真实已执行步骤恢复。
            predecessor = {"tree-builder": "decomposition-auditor", "suspicion-scanner": "tree-auditor",
                           "local-reviewer": "suspicion-scanner", "obligation-builder": "local-reviewer",
                           "check-object-generator": "obligation-builder", "numeric-evaluator": "check-object-generator",
                           "statement-formalizer": "check-object-generator", "proof-searcher": "semantic-checker",
                           "scoring": "consistency-auditor"}.get(role)
            if predecessor:
                parent = latest_roles.get((predecessor, _role_scope(predecessor, parameters)))
                if parent:
                    parents.add(parent)
            obligation, branch = parameters.get("obligation_id"), parameters.get("branch")
            if role == "semantic-checker":
                parent = latest_compiles.get((obligation, branch, "statement"))
                if parent:
                    parents.add(parent)
            if role == "statement-formalizer" and branch in {"negation", "counterexample"}:
                parent = branch_terminals.get((obligation, "original" if branch == "negation" else "negation"))
                if parent:
                    parents.add(parent)
            if role == "local-reviewer":
                prefix_key = latest_roles.get(("prefix-auditor", None))
                prefix_response = previous.get(prefix_key, {}).get("response")
                prefix_response = prefix_response if isinstance(prefix_response, dict) else {}
                prefix_result = prefix_response.get("result") if isinstance(prefix_response.get("result"), dict) else {}
                request_parameters = request.get("parameters") if isinstance(request.get("parameters"), dict) else {}
                window = request_parameters.get("window")
                try:
                    window = json.loads(window) if isinstance(window, str) else []
                except ValueError:
                    window = []
                candidates = prefix_result.get("candidate_units")
                candidates = candidates if isinstance(candidates, list) else []
                window = window if isinstance(window, list) else []
                if prefix_key and any(candidate in window for candidate in candidates if isinstance(candidate, str)):
                    parents.add(prefix_key)
            if role == "evidence-mapper":
                scan = latest_roles.get(("suspicion-scanner", None))
                if scan:
                    parents.add(scan)
                for path, content in inputs.items():
                    match = re.fullmatch(rf"faithsieve-work/formal/({_OBLIGATION})-verification\.json", path)
                    if not match or not isinstance(content, str):
                        continue
                    try:
                        verification = json.loads(content)
                    except ValueError:
                        continue
                    if not isinstance(verification, dict):
                        continue
                    obligation = match[1]
                    numeric = latest_roles.get(("numeric-evaluator", obligation))
                    if verification.get("route") == "numeric" and numeric:
                        parents.add(numeric)
                    elif verification.get("route") == "lean":
                        branch = verification.get("branch")
                        if branch:
                            terminal = latest_compiles.get((obligation, branch, "proof")) or branch_terminals.get((obligation, branch))
                            if terminal:
                                parents.add(terminal)
                        else:
                            parents.update(terminal for (identifier, _branch), terminal in branch_terminals.items() if identifier == obligation)
        revision = request.get("revision_report")
        audit_role = {"decomposer": "decomposition-auditor", "tree-builder": "tree-auditor",
                      "statement-formalizer": "semantic-checker", "final-synthesizer": "consistency-auditor"}.get(role)
        if isinstance(revision, str) and revision:
            for parent, prior in reversed(list(previous.items())):
                response = prior.get("response") if isinstance(prior.get("response"), dict) else {}
                result = response.get("result") if isinstance(response.get("result"), dict) else {}
                report = result.get("report")
                artifact = response.get("artifacts", {}).get(result.get("artifact")) if isinstance(response.get("artifacts"), dict) else None
                same_scope = _role_scope(audit_role, _parameters(prior["request"])) == _role_scope(audit_role, parameters)
                if prior["request"].get("role") == audit_role and same_scope and isinstance(report, str) and report and (revision == report or (isinstance(artifact, str) and revision == report + "\n" + artifact)):
                    parents.add(parent)
                    break
        if key.endswith("-attempt-2") and key.removesuffix("2") + "1" in previous:
            parents.add(key.removesuffix("2") + "1")
        # 只接受已位于当前节点之前的依赖；因此修订和补查展开后仍然无环。
        parents.intersection_update(previous)
        reduced = {parent for parent in parents if not any(parent in ancestors.get(other, set()) for other in parents if other != parent)}
        edges.extend({"source": parent, "target": key} for parent in sorted(reduced, key=list(previous).index))
        ancestors[key] = parents | set().union(*(ancestors.get(parent, set()) for parent in parents))
        previous[key] = record
        if record["state"] == "completed":
            latest_roles[(role, _role_scope(role, parameters))] = key
            if parameters.get("obligation_id") and parameters.get("branch"):
                branch_terminals[(parameters["obligation_id"], parameters["branch"])] = key
            if role == "lean-compiler":
                latest_compiles[(parameters.get("obligation_id"), parameters.get("branch"), parameters.get("target"))] = key
            outputs = _outputs(key, record)
            response = record.get("response") if isinstance(record.get("response"), dict) else {}
            result_path = request.get("expected_result_path")
            if isinstance(result_path, str) and isinstance(response.get("result"), dict):
                outputs[result_path + ".transport.json"] = json.dumps({"control": response.get("control", {}), "execution": response.get("execution", {})}, ensure_ascii=False, indent=2)
            for path, content in outputs.items():
                producers.setdefault(path, []).append((key, content))
    return edges


def _snapshot(root_fd, run):
    summary = {}
    records = _records(root_fd, summary)
    snapshot = {"stages": [], "source": {}, "artifacts": [], "warnings": [], "edges": [], "summary": summary}
    if summary["truncated"]:
        snapshot["warnings"].append(f"本次图仅展示已读取的 {summary['shown_stage_count']}/{summary['stage_count']} 个步骤；其余记录未载入，评测不受展示预算影响。")
    if any(sequence is None for _key, _record, _info, sequence in records):
        snapshot["warnings"].append("部分历史检查点未记录调用顺序，按文件更新时间展示；修订和编译的先后可能无法完整恢复。")
    latest, owners, trees, parsed_trees = {}, {}, {}, {}
    for key, record, info, sequence in records:
        request = record["request"]
        role = "image-render" if key == "image-render" else "source-extraction" if key == "source-extraction" else "scoring" if key == "final-scoring" else "lean-compiler" if key.startswith("compile-") else request.get("role")
        if role not in _LABELS:
            raise FaithSieveViewError("FaithSieve 步骤角色无效")
        response = record.get("response") if record["state"] != "endpoint_error" and isinstance(record.get("response"), dict) else {}
        result = response.get("result") if isinstance(response.get("result"), dict) else response
        outputs = _outputs(key, record)
        stage = {"key": key, "sequence": sequence, "role": role, "label": _LABELS[role],
                 "kind": "code" if role in {"image-render", "lean-compiler"} else "judge" if role in _JUDGE_ROLES else "llm",
                 "state": record["state"], "status": _text(result.get("status") or result.get("verdict"), 64),
                 "report": _text(result.get("report") or result.get("comment")),
                 "parameters": _parameters(request), "created_at": _timestamp(record.get("created_at")),
                 "updated_at": _timestamp(record.get("updated_at")) or datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat(),
                 "session_id": None, "task_id": None, "artifacts": [], "checks": []}
        if request.get("proof_graph_version") == 3:
            stage["label"] = {"tree-builder": "生成证明依赖图", "tree-auditor": "审核证明依赖图"}.get(role, stage["label"])
        elif request.get("proof_graph_version") == 2:
            stage["label"] = {"tree-builder": "建立证明依赖图", "tree-auditor": "独立审计证明依赖图",
                              "local-reviewer": "局部复核结论节点"}.get(role, stage["label"])
        attempt = re.search(r"-attempt-([12])$", key)
        if attempt:
            stage["parameters"]["attempt"] = int(attempt[1])
        if record["state"] == "protocol_error":
            # 原错误可能包含模型协议输入；仅公开固定状态说明。
            stage["report"] = "角色回传未通过协议校验。"
        elif record["state"] == "endpoint_error":
            metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
            try:
                message = endpoint_error_message(metadata.get("endpoint_error"))
            except FaithSieveProtocolError:
                message = "模型端点调用失败。"
            stage.update(status="failed", report=f"{stage['label']}：{message}")
        if _node_selection_fallback(record) is not None:
            stage.update(state="completed", status="default_order", report=NODE_SELECTION_FALLBACK_REASON)
        if role in _JUDGE_ROLES:
            stage.update(_judge(root_fd, run, key, role, record=record))
        if role == "lean-compiler":
            code = response.get("exit_code")
            if isinstance(code, int) and not isinstance(code, bool):
                stage.update(exit_code=code, status="passed" if code == 0 else "failed", report=_text(response.get("diagnostics")))
        if role == "numeric-evaluator" and isinstance(response.get("execution"), dict):
            execution = response["execution"]
            if execution.get("tool_executed") is True:
                stage["checks"].append({"label": "独立精确符号复验", "kind": "code", "state": "completed",
                                        "status": _text(execution.get("status"), 64),
                                        "report": _text(execution.get("stdout")) + _text(execution.get("stderr")),
                                        "exit_code": execution.get("exit_code") if isinstance(execution.get("exit_code"), int) and not isinstance(execution.get("exit_code"), bool) else None})
        for path, content in sorted(outputs.items()):
            stage["artifacts"].append(_artifact_metadata(path, content, stage_key=key))
            latest[path] = content
            owners.setdefault(path, []).append(key)
            if role == "tree-builder" and path in {TREE_PATH, "faithsieve-work/tree.md"}:
                files = request.get("files") if isinstance(request.get("files"), dict) else {}
                steps = files.get("faithsieve-work/steps.md")
                tree, tree_format = proof_tree_projection(path, content, steps_markdown=steps if isinstance(steps, str) else "")
                if tree is not None:
                    trees[tree_format] = {"path": path, "stage_key": key, "format": tree_format}
                    parsed_trees[tree_format] = tree
                    if tree_format == "dependency_dag":
                        trees[tree_format]["schema_version"] = tree["schema_version"]
                        stage["artifacts"][-1]["format"] = tree_format
                        stage["artifacts"][-1]["schema_version"] = tree["schema_version"]
        if role == "source-extraction":
            preprocessing = _preprocessing(root_fd)
            environment = _environment(root_fd)
            stage["checks"] = [check for check in (environment, preprocessing) if check]
            snapshot["source"] = {"status": stage["status"], "report": stage["report"],
                                  "artifact": "faithsieve-work/source/submission.md" if "faithsieve-work/source/submission.md" in outputs else None,
                                  "preprocessing": preprocessing, "environment": environment}
        snapshot["stages"].append(stage)
    extras = {"problem.md", "faithsieve_result.json", "faithsieve-work/source/extraction.json", NODE_VERIFICATION_PATH}
    for stage in snapshot["stages"]:
        obligation = stage["parameters"].get("obligation_id")
        if obligation:
            extras.add(f"faithsieve-work/formal/{obligation}-verification.json")
    for path in sorted(extras):
        try:
            content, _info = _read(root_fd, path)
        except FileNotFoundError:
            continue
        latest[path] = content
    snapshot["artifacts"] = [{**_artifact_metadata(path, content), "stage_keys": owners.get(path, [])} for path, content in sorted(latest.items())]
    snapshot["edges"] = _dag(records, snapshot["stages"], snapshot["warnings"])
    if trees:
        snapshot["proof_tree"] = trees.get("dependency_dag") or trees.get("json") or trees["legacy_markdown"]
        if snapshot["proof_tree"]["format"] == "dependency_dag":
            verification = node_verification_projection(root_fd, parsed_trees["dependency_dag"])
            if verification is not None:
                snapshot["proof_tree"]["node_verification"] = verification
    return snapshot


def workflow_snapshot(run):
    """管理员鉴权由调用入口负责；这里只读取该 run 已存在的数学记录。"""
    try:
        with _workspace(run) as root_fd:
            return _snapshot(root_fd, run)
    except FileNotFoundError:
        return {"stages": [], "source": {}, "artifacts": [], "warnings": [], "edges": [],
                "summary": {"stage_count": 0, "shown_stage_count": 0, "truncated": False}}


def read_artifact(run, path, *, stage_key=None):
    """读取当前工件或指定轮次的原文；隐藏所有请求、密钥和内部状态文件。"""
    if not _artifact_allowed(path) or (stage_key is not None and (not isinstance(stage_key, str) or not _KEY.fullmatch(stage_key))):
        raise FaithSieveArtifactNotFoundError("FaithSieve 工件不存在")
    try:
        with _workspace(run) as root_fd:
            if stage_key is not None:
                record, info = _json(root_fd, f"faithsieve-work/checkpoints/{stage_key}.json")
                if record.get("state") not in {"pending", "completed", "protocol_error", "endpoint_error"} or not isinstance(record.get("request"), dict):
                    raise FaithSieveViewError("FaithSieve 步骤状态无效")
                records = [(stage_key, record, info, record.get("sequence"))]
            else:
                records = _records(root_fd)
            content = None
            tree_steps = ""
            for key, record, _info, _sequence in records:
                if stage_key is None or key == stage_key:
                    outputs = _outputs(key, record)
                    if path in outputs:
                        content = outputs[path]
                        files = record["request"].get("files")
                        tree_steps = files.get("faithsieve-work/steps.md", "") if isinstance(files, dict) else ""
            if stage_key is not None and content is None:
                raise FaithSieveArtifactNotFoundError("FaithSieve 阶段工件不存在")
            if stage_key is None:
                snapshot = _snapshot(root_fd, run)
                if path not in {item["path"] for item in snapshot["artifacts"]}:
                    raise FaithSieveArtifactNotFoundError("FaithSieve 工件不存在")
                # 原文优先取最后一个已完成检查点，防止修订覆盖历史产物。
                if content is None:
                    content, _info = _read(root_fd, path)
            result = _artifact_metadata(path, content, stage_key=stage_key)
            result.update(content=content, mime_type="text/plain; charset=utf-8")
            tree, tree_format = proof_tree_projection(path, content, steps_markdown=tree_steps if isinstance(tree_steps, str) else "")
            if tree is not None:
                result.update(proof_tree=tree, proof_tree_format=tree_format)
                if tree_format == "dependency_dag":
                    verification = node_verification_projection(root_fd, tree)
                    if verification is not None:
                        result["proof_node_verification"] = verification
            return result
    except FileNotFoundError:
        raise FaithSieveArtifactNotFoundError("FaithSieve 工件不存在") from None


__all__ = ["workflow_snapshot", "read_artifact", "FaithSieveViewError", "FaithSieveArtifactNotFoundError"]
