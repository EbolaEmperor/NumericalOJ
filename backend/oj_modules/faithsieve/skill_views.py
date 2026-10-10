"""原 FaithSieve skill 单 Judge 会话及数学产物的安全只读展示。"""

from contextlib import contextmanager
import json
import os
import re
import stat

from backend.oj_modules.agents.judge import judge_session_id
from backend.oj_modules.agents.sessions import agent_status_is_terminal, get_agent_session
from backend.oj_modules.submissions.faithsieve import normalize_execution_mode, parse_result

from . import views


_STAGE_KEY = "skill-judge"
_MAX_ARTIFACTS = 512
_MAX_TOTAL_BYTES = 16 * 1024 * 1024
_DIRECTORIES = re.compile(r"faithsieve-work(?:/(?:source|review|formal|results|obligations|verification)(?:/[EN][1-9][0-9]*)?)?\Z")


def _identity(run):
    if normalize_execution_mode(run.get("execution_mode"), default="skill") != "skill":
        raise views.FaithSieveViewError("FaithSieve 执行方式与会话不一致")
    attempt = run.get("attempt_id")
    if not isinstance(attempt, str) or not re.fullmatch(r"[a-f0-9]{32}", attempt):
        raise views.FaithSieveViewError("FaithSieve 请求编号无效")
    submission = run.get("submission_id")
    if isinstance(submission, bool) or not isinstance(submission, int) or submission < 1:
        raise views.FaithSieveViewError("FaithSieve 提交编号无效")
    # 沿用历史 Judge 的既有身份入口，不创建新的文件版本或内容校验机制。
    session_id = judge_session_id(submission, attempt, "faithsieve")
    task_id = f"fs-{attempt}"
    if run.get("session_id") and run["session_id"] != session_id:
        raise views.FaithSieveViewError("FaithSieve skill 会话身份不一致")
    return session_id, task_id


def _session(run):
    session_id, task_id = _identity(run)
    if not run.get("session_id"):
        return None
    session = get_agent_session(session_id)
    if not session:
        return None
    expected = {
        "session_id": session_id, "current_task_id": task_id,
        "task_kind": "judge", "judge_kind": "faithsieve",
        "submission_id": run["submission_id"], "attempt_id": run["attempt_id"],
        "problem_id": run.get("problem_id"), "requested_by": run.get("username"),
        "harness": run.get("runtime", {}).get("harness"),
        "endpoint_id": run.get("runtime", {}).get("endpoint_id"), "endpoint_source": "global",
    }
    if any(session.get(key) != value for key, value in expected.items()):
        raise views.FaithSieveViewError("FaithSieve skill Judge 归属不一致")
    return session


@contextmanager
def _workspace(run):
    session_id, _task_id = _identity(run)
    root = views.workspace_store._workspace_root()
    opened = []
    try:
        fd = os.open(root.anchor, views._DIR_FLAGS)
        opened.append(fd)
        for part in (*root.parts[1:], "sessions", session_id, "workspace"):
            fd = os.open(part, views._DIR_FLAGS, dir_fd=fd)
            opened.append(fd)
        yield fd
    except FileNotFoundError:
        raise
    except OSError:
        raise views.FaithSieveViewError("FaithSieve skill 工作区无法安全读取") from None
    finally:
        for fd in reversed(opened):
            os.close(fd)


def _paths(root_fd, path=""):
    @contextmanager
    def directory():
        if not path:
            yield root_fd
        else:
            with views._directory(root_fd, path) as fd:
                yield fd
    with directory() as fd:
        for name in sorted(os.listdir(fd)):
            if name.startswith("."):
                continue
            candidate = f"{path}/{name}" if path else name
            if views._artifact_allowed(candidate):
                yield candidate
            elif _DIRECTORIES.fullmatch(candidate):
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    yield from _paths(root_fd, candidate)


def _content(root_fd, path):
    content, _info = views._read(root_fd, path)
    if path == "faithsieve_result.json":
        try:
            parse_result(json.loads(content))
        except (TypeError, ValueError):
            raise views.FaithSieveViewError("FaithSieve skill 结果格式无效") from None
    return content


def skill_snapshot(run):
    """只展示实际单会话，不推断 skill 内部角色、调用顺序或 DAG。"""
    session = _session(run)
    snapshot = {"stages": [], "source": {}, "artifacts": [], "edges": [], "warnings": [],
                "summary": {"stage_count": 0, "shown_stage_count": 0, "truncated": False}}
    if session:
        terminal = agent_status_is_terminal(session.get("status"))
        stage = {
            "key": _STAGE_KEY, "sequence": None, "role": "skill", "label": "FaithSieve skill Judge",
            "kind": "judge", "state": "completed" if terminal else "pending",
            "status": views._text(run.get("status"), 64), "judge_status": views._text(session.get("status"), 64),
            "report": views._text(session.get("message")), "parameters": {},
            "created_at": session.get("created_at"), "updated_at": session.get("updated_at"),
            "session_id": session["session_id"], "task_id": session["current_task_id"],
            "artifacts": [], "checks": [],
        }
        snapshot["stages"].append(stage)
        snapshot["summary"].update(stage_count=1, shown_stage_count=1)
    else:
        return snapshot
    total = 0
    try:
        with _workspace(run) as fd:
            for path in _paths(fd):
                content = _content(fd, path)
                size = len(content.encode("utf-8"))
                if len(snapshot["artifacts"]) >= _MAX_ARTIFACTS or total + size > _MAX_TOTAL_BYTES:
                    snapshot["warnings"].append("skill 数学产物较多，本页只列出部分文件；评测执行不受展示预算影响。")
                    break
                total += size
                metadata = views._artifact_metadata(path, content, stage_key=_STAGE_KEY)
                snapshot["artifacts"].append({**metadata, "stage_keys": [_STAGE_KEY]})
                stage["artifacts"].append(metadata)
                tree, tree_format = views.proof_tree_projection(path, content)
                if tree_format == "dependency_dag":
                    metadata["format"] = tree_format
                    metadata["schema_version"] = tree["schema_version"]
                    snapshot["artifacts"][-1]["format"] = tree_format
                    snapshot["artifacts"][-1]["schema_version"] = tree["schema_version"]
                rank = {"legacy_markdown": 0, "json": 1, "dependency_dag": 2}
                if tree is not None and rank[tree_format] >= rank.get(snapshot.get("proof_tree", {}).get("format"), -1):
                    snapshot["proof_tree"] = {"path": path, "stage_key": _STAGE_KEY, "format": tree_format}
                    if tree_format == "dependency_dag":
                        snapshot["proof_tree"]["schema_version"] = tree["schema_version"]
                        verification = views.node_verification_projection(fd, tree)
                        if verification is not None:
                            snapshot["proof_tree"]["node_verification"] = verification
    except FileNotFoundError:
        pass
    return snapshot


def read_skill_artifact(run, path, *, stage_key=None):
    if not views._artifact_allowed(path) or stage_key not in {None, _STAGE_KEY}:
        raise views.FaithSieveArtifactNotFoundError("FaithSieve skill 工件不存在")
    if _session(run) is None:
        raise views.FaithSieveArtifactNotFoundError("FaithSieve skill Judge 不存在")
    try:
        with _workspace(run) as fd:
            content = _content(fd, path)
            tree, tree_format = views.proof_tree_projection(path, content)
            verification = views.node_verification_projection(fd, tree) if tree_format == "dependency_dag" else None
    except FileNotFoundError:
        raise views.FaithSieveArtifactNotFoundError("FaithSieve skill 工件不存在") from None
    metadata = views._artifact_metadata(path, content)
    result = {**metadata, "content": content, "mime_type": "text/plain; charset=utf-8"}
    if tree is not None:
        result.update(proof_tree=tree, proof_tree_format=tree_format)
        if verification is not None:
            result["proof_node_verification"] = verification
    return result


__all__ = ["skill_snapshot", "read_skill_artifact"]
