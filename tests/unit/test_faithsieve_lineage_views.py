"""复用检查点只链接完整来源一致的已完成 Judge，不公开私有预检材料。"""

from copy import deepcopy
import json
import os

import pytest

from backend.oj_modules.faithsieve import views
from backend.oj_modules.faithsieve.checkpoints import CheckpointStore
from tests.unit.test_faithsieve_views import saved


KEY = "role-000010-attempt-1"
SOURCE = "b" * 32
SECOND_SOURCE = "c" * 32
SECOND_KEY = "role-000034-attempt-1"
PRIVATE = views._LINEAGE_FILENAME


@pytest.fixture
def imported(saved, monkeypatch):
    saved.run.update(execution_mode="workflow", problem_id=5,
                     runtime={"harness": "pi", "endpoint_id": 7})
    source = {**saved.run, "attempt_id": SOURCE, "session_id": f"faithsieve-{SOURCE}",
              "status": "inconclusive", "harness": "pi", "endpoint_id": 7}
    source.pop("runtime")
    source_workspace = saved.root / "sessions" / source["session_id"] / "workspace"
    source_workspace.mkdir(parents=True)
    sid, tid = f"fs-{SOURCE}-{KEY}", f"ft-{SOURCE}-{KEY}"
    request = {"role": "local-verifier", "proof_graph_version": 3, "local_diagnostic_version": 1,
               "parameters": {"node_id": "N11"}, "files": {"private-input": "SECRET-INPUT"},
               "expected_result_path": "faithsieve-work/results/N11-local-verifier.json"}
    artifact = "faithsieve-work/verification/N11.md"
    payload = {"result": {"status": "passed", "artifact": artifact, "report": "命题成立", "diagnostics": []},
               "artifacts": {artifact: "完整验证报告"}, "control": {},
               "execution": {"provider": "numoj-agent-judge", "session_id": sid, "task_id": tid,
                             "credential": "SECRET-EXECUTION"}}
    saved.store.put(KEY, request, state="completed", response=deepcopy(payload))
    source_store = CheckpointStore(source_workspace)
    source_store.put(KEY, deepcopy(request), state="completed", response=deepcopy(payload))
    native = source_workspace / "faithsieve-work/judge-invocations" / f"{KEY}.json"
    native.parent.mkdir(parents=True)
    native.write_text(json.dumps({"session_id": sid, "task_id": tid, "role": "local-verifier",
                                 "proof_graph_version": 3, "prompt": "SECRET-PROMPT"}))
    session = {"session_id": sid, "current_task_id": tid, "task_kind": "judge", "judge_kind": "faithsieve",
               "attempt_id": SOURCE, "submission_id": source["submission_id"], "problem_id": 5,
               "requested_by": source["requested_by"], "harness": "pi", "endpoint_id": 7, "status": "Completed"}
    saved.sessions[sid] = session
    lineage = {"source_attempt": SOURCE, "destination_attempt": saved.run["attempt_id"],
               "created_at": "2026-10-10T00:00:00+00:00", "source_prefix_keys": [KEY],
               "boundary_key": "role-000023-attempt-1", "reason": "SECRET-REASON",
               "native_origins": [{"key": KEY, "origin_session": sid, "origin_task": tid, "status": "passed"}],
               "database_preflight": {"opaque": "SECRET-PREFLIGHT"}}
    path = saved.write(PRIVATE, lineage)
    path.chmod(0o600)
    calls = []
    def get_run(attempt):
        calls.append(attempt)
        return source if attempt == SOURCE else None
    monkeypatch.setattr(views, "get_run", get_run)
    saved.source = source
    saved.source_workspace = source_workspace
    saved.source_store = source_store
    saved.lineage = lineage
    saved.lineage_path = path
    saved.source_session = session
    saved.origin = lineage["native_origins"][0]
    saved.source_calls = calls
    def save_lineage():
        path.write_text(json.dumps(saved.lineage, ensure_ascii=False))
        path.chmod(0o600)
    saved.save_lineage = save_lineage
    return saved


@pytest.fixture
def mixed(imported, monkeypatch):
    source = {**imported.source, "attempt_id": SECOND_SOURCE,
              "session_id": f"faithsieve-{SECOND_SOURCE}", "status": "completed"}
    workspace = imported.root / "sessions" / source["session_id"] / "workspace"
    workspace.mkdir(parents=True)
    source_store = CheckpointStore(workspace)
    original = imported.store.records()[KEY]
    request = deepcopy(original["request"])
    request.update(parameters={"node_id": "N14"}, expected_result_path="faithsieve-work/results/N14-local-verifier.json")
    artifact = "faithsieve-work/verification/N14.md"
    sid, tid = f"fs-{SECOND_SOURCE}-{SECOND_KEY}", f"ft-{SECOND_SOURCE}-{SECOND_KEY}"
    response = deepcopy(original["response"])
    response["result"]["artifact"] = artifact
    response["artifacts"] = {artifact: "第二来源完整报告"}
    response["execution"].update(session_id=sid, task_id=tid)
    imported.store.put(SECOND_KEY, request, state="completed", response=deepcopy(response))
    source_store.put(SECOND_KEY, deepcopy(request), state="completed", response=deepcopy(response))
    manifest = workspace / "faithsieve-work/judge-invocations" / f"{SECOND_KEY}.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({"session_id": sid, "task_id": tid, "role": "local-verifier",
                                    "proof_graph_version": 3, "prompt": "SECRET-SECOND-PROMPT"}))
    session = {**imported.source_session, "session_id": sid, "current_task_id": tid, "attempt_id": SECOND_SOURCE}
    imported.sessions[sid] = session
    origin = {"key": SECOND_KEY, "origin_session": sid, "origin_task": tid,
              "status": "passed", "source_attempt": SECOND_SOURCE}
    imported.lineage["source_prefix_keys"].append(SECOND_KEY)
    imported.lineage["native_origins"].append(origin)
    imported.lineage["boundary_key"] = "role-000042-attempt-1"
    imported.save_lineage()
    sources = {SOURCE: imported.source, SECOND_SOURCE: source}
    def get_run(attempt):
        imported.source_calls.append(attempt)
        return sources.get(attempt)
    monkeypatch.setattr(views, "get_run", get_run)
    imported.second_source = source
    imported.second_workspace = workspace
    imported.second_store = source_store
    imported.second_manifest = manifest
    imported.second_session = session
    imported.second_origin = origin
    return imported


def snapshot_files(root):
    return {path: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
            for path in root.rglob("*") if path.is_file()}


def stage(imported):
    return views.workflow_snapshot(imported.run)["stages"][0]


def test_imported_completed_judge_links_original_session_without_writes_or_private_data(imported):
    before = snapshot_files(imported.root)
    result = views.workflow_snapshot(imported.run)
    value = result["stages"][0]
    assert value["session_id"] == imported.origin["origin_session"]
    assert value["task_id"] == imported.origin["origin_task"]
    assert value["judge_status"] == "Completed" and value["status"] == "passed"
    assert imported.source_calls == [SOURCE]
    assert "SECRET" not in json.dumps(result)
    assert not (imported.workspace / "faithsieve-work/judge-invocations").exists()
    assert views.read_artifact(imported.run, "faithsieve-work/verification/N11.md", stage_key=KEY)["content"] == "完整验证报告"
    assert snapshot_files(imported.root) == before
    with pytest.raises(views.FaithSieveArtifactNotFoundError):
        views.read_artifact(imported.run, PRIVATE)


@pytest.mark.parametrize("condition", ["absent_lineage", "not_in_prefix", "not_in_origins", "pending", "wrong_version"])
def test_execution_alone_never_grants_source_link(imported, condition):
    if condition == "absent_lineage":
        imported.lineage_path.unlink()
    elif condition == "not_in_prefix":
        imported.lineage["source_prefix_keys"] = ["role-000009-attempt-1"]
        imported.lineage["native_origins"] = []
        imported.save_lineage()
    elif condition == "not_in_origins":
        imported.lineage["native_origins"] = []
        imported.save_lineage()
    else:
        record = imported.store.records()[KEY]
        if condition == "wrong_version":
            record["request"]["proof_graph_version"] = 2
        else:
            record["state"] = "pending"
        imported.store._path(KEY).write_text(json.dumps(record))
    assert stage(imported)["session_id"] is None
    assert imported.source_calls == []


@pytest.mark.parametrize("field,value", [("problem_id", 999), ("submission_id", 999), ("requested_by", "其他管理员"),
                                         ("harness", "other"), ("endpoint_id", 999), ("endpoint_id", 7.0),
                                         ("attempt_id", "c" * 32), ("execution_mode", "skill"), ("status", "running")])
def test_source_run_identity_must_match_destination(imported, field, value):
    imported.source[field] = value
    with pytest.raises(views.FaithSieveViewError, match="归属|配置"):
        stage(imported)


@pytest.mark.parametrize("change", ["request", "response", "typed_value", "state"])
def test_source_full_canonical_checkpoint_is_required(imported, change):
    record = imported.source_store.records()[KEY]
    if change == "request":
        record["request"]["files"]["private-input"] += "改动"
    elif change == "response":
        record["response"]["artifacts"]["faithsieve-work/verification/N11.md"] += "改动"
    elif change == "typed_value":
        record["request"]["proof_graph_version"] = 3.0
    else:
        record["state"] = "pending"
    imported.source_store._path(KEY).write_text(json.dumps(record))
    with pytest.raises(views.FaithSieveViewError, match="完整输入或结果"):
        stage(imported)


@pytest.mark.parametrize("field,value", [("submission_id", 999), ("problem_id", 999), ("attempt_id", "c" * 32),
                                         ("requested_by", "其他管理员"), ("harness", "other"), ("endpoint_id", 999),
                                         ("current_task_id", "other-task"), ("status", "Running")])
def test_source_native_session_keeps_existing_ownership_and_completion_guards(imported, field, value):
    imported.source_session[field] = value
    with pytest.raises(views.FaithSieveViewError, match="归属|完成"):
        stage(imported)


@pytest.mark.parametrize("field,value", [("destination_attempt", "c" * 32), ("source_attempt", "../outside"),
                                         ("source_prefix_keys", [KEY, KEY]), ("boundary_key", KEY),
                                         ("unrecognized", "SECRET-EXTRA")])
def test_lineage_contract_cannot_redirect_or_expand_trust(imported, field, value):
    imported.lineage[field] = value
    imported.save_lineage()
    with pytest.raises(views.FaithSieveViewError, match="来源"):
        stage(imported)


@pytest.mark.parametrize("field,value", [("origin_session", "foreign-session"), ("origin_task", "foreign-task"),
                                         ("origin_task", []), ("status", "refuted"), ("key", "role-000012-attempt-1")])
def test_origin_and_execution_must_describe_same_actual_judge(imported, field, value):
    imported.lineage["native_origins"][0][field] = value
    imported.save_lineage()
    with pytest.raises(views.FaithSieveViewError, match="来源"):
        stage(imported)


@pytest.mark.parametrize("change", ["provider", "session_id", "task_id"])
def test_even_equal_canonical_records_cannot_self_authorize_arbitrary_execution(imported, change):
    for store in (imported.store, imported.source_store):
        record = store.records()[KEY]
        record["response"]["execution"][change] = "foreign"
        store._path(KEY).write_text(json.dumps(record))
    with pytest.raises(views.FaithSieveViewError, match="执行记录"):
        stage(imported)


@pytest.mark.parametrize("missing", ["source_run", "source_workspace", "source_checkpoint", "source_native", "source_session"])
def test_missing_source_evidence_omits_link_without_recreating_material(imported, monkeypatch, missing):
    if missing == "source_run":
        monkeypatch.setattr(views, "get_run", lambda _attempt: None)
    elif missing == "source_workspace":
        imported.source_workspace.rename(imported.source_workspace.with_name("removed"))
    elif missing == "source_checkpoint":
        imported.source_store._path(KEY).unlink()
    elif missing == "source_native":
        (imported.source_workspace / "faithsieve-work/judge-invocations" / f"{KEY}.json").unlink()
    else:
        imported.sessions.clear()
    before = snapshot_files(imported.root)
    assert stage(imported)["session_id"] is None
    assert snapshot_files(imported.root) == before


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "public_mode", "oversized", "duplicate", "constant"])
def test_lineage_file_rejects_unsafe_or_ambiguous_inputs(imported, tmp_path, kind):
    raw = imported.lineage_path.read_bytes()
    if kind in {"symlink", "hardlink"}:
        source = tmp_path / "foreign.json"
        source.write_bytes(raw)
        source.chmod(0o600)
        imported.lineage_path.unlink()
        if kind == "symlink":
            imported.lineage_path.symlink_to(source)
        else:
            os.link(source, imported.lineage_path)
    elif kind == "public_mode":
        imported.lineage_path.chmod(0o644)
    elif kind == "oversized":
        with imported.lineage_path.open("wb") as stream:
            stream.truncate(views._LINEAGE_LIMIT + 1)
    elif kind == "duplicate":
        imported.lineage_path.write_text(raw.decode()[:-1] + ',"source_attempt":"' + SOURCE + '"}')
    else:
        imported.lineage_path.write_text(raw.decode()[:-1] + ',"database_preflight":NaN}')
    with pytest.raises(views.FaithSieveViewError, match="来源"):
        stage(imported)


def test_current_attempt_native_manifest_takes_precedence_over_lineage(imported, monkeypatch):
    sid, tid = imported.native(KEY, "local-verifier")
    imported.sessions[sid].update(problem_id=5, harness="pi", endpoint_id=7)
    imported.lineage_path.write_text("not JSON")
    monkeypatch.setattr(views, "get_run", lambda _attempt: pytest.fail("原生本次 Judge 不读取来源"))
    value = stage(imported)
    assert value["session_id"] == sid and value["task_id"] == tid


def test_cached_lineage_preserves_original_continuation_task_guard(imported):
    from backend.oj_modules.faithsieve.judge import _continuation_prompt

    native = imported.source_workspace / "faithsieve-work/judge-invocations" / f"{KEY}.json"
    saved_native = json.loads(native.read_text())
    saved_native["timeout_seconds"] = 600
    saved_native["result_path"] = "faithsieve-work/results/N11-local-verifier.json"
    native.write_text(json.dumps(saved_native))
    task = imported.origin["origin_task"] + "-c1"
    continuation = {"kind": "native_timeout", "session_id": imported.origin["origin_session"],
                    "failed_task_id": imported.origin["origin_task"], "original_timeout_seconds": 600,
                    "continuation_task_id": task, "continuation_timeout_seconds": 3600,
                    "continuation_prompt": _continuation_prompt(saved_native["result_path"])}
    path = native.parent / KEY / "continuation.json"
    path.parent.mkdir()
    path.write_text(json.dumps(continuation))
    imported.origin["origin_task"] = task
    imported.source_session["current_task_id"] = task
    imported.save_lineage()
    for store in (imported.store, imported.source_store):
        record = store.records()[KEY]
        record["response"]["execution"]["task_id"] = task
        store._path(KEY).write_text(json.dumps(record))
    assert stage(imported)["task_id"] == task


def test_mixed_sources_link_each_original_completed_judge_without_private_data_or_writes(mixed):
    before = snapshot_files(mixed.root)
    snapshot = views.workflow_snapshot(mixed.run)
    stages = snapshot["stages"]
    assert [item["session_id"] for item in stages] == [mixed.origin["origin_session"], mixed.second_origin["origin_session"]]
    assert [item["task_id"] for item in stages] == [mixed.origin["origin_task"], mixed.second_origin["origin_task"]]
    assert all(item["judge_status"] == "Completed" for item in stages)
    assert mixed.source_calls == [SOURCE, SECOND_SOURCE]
    assert "SECRET" not in json.dumps(snapshot)
    assert "database_preflight" not in json.dumps(snapshot)
    assert snapshot_files(mixed.root) == before


@pytest.mark.parametrize("value", [None, True, 3, "C" * 32, "c" * 31, "../outside", "a" * 32, SOURCE])
def test_entry_source_attempt_is_exact_and_matches_actual_native_identity(mixed, value):
    mixed.second_origin["source_attempt"] = value
    mixed.save_lineage()
    with pytest.raises(views.FaithSieveViewError, match="来源"):
        views.workflow_snapshot(mixed.run)


@pytest.mark.parametrize("field,value", [("problem_id", 999), ("submission_id", 999), ("requested_by", "其他管理员"),
                                         ("harness", "other"), ("endpoint_id", 999), ("endpoint_id", 7.0),
                                         ("attempt_id", SOURCE), ("status", "running")])
def test_mixed_entry_uses_its_own_source_run_ownership_and_terminal_guards(mixed, field, value):
    mixed.second_source[field] = value
    with pytest.raises(views.FaithSieveViewError, match="归属|配置"):
        views.workflow_snapshot(mixed.run)


@pytest.mark.parametrize("field,value", [("problem_id", 999), ("submission_id", 999), ("requested_by", "其他管理员"),
                                         ("endpoint_id", 999), ("attempt_id", SOURCE), ("status", "Running")])
def test_mixed_entry_requires_actual_completed_session_of_that_source(mixed, field, value):
    mixed.second_session[field] = value
    with pytest.raises(views.FaithSieveViewError, match="归属|完成"):
        views.workflow_snapshot(mixed.run)


@pytest.mark.parametrize("change", ["request", "typed_value", "result"])
def test_mixed_entry_requires_full_typed_original_checkpoint(mixed, change):
    record = mixed.second_store.records()[SECOND_KEY]
    if change == "request":
        record["request"]["files"]["private-input"] += "改动"
    elif change == "typed_value":
        record["request"]["proof_graph_version"] = 3.0
    else:
        record["response"]["result"]["report"] += "改动"
    mixed.second_store._path(SECOND_KEY).write_text(json.dumps(record))
    with pytest.raises(views.FaithSieveViewError, match="完整输入或结果"):
        views.workflow_snapshot(mixed.run)


def test_mixed_source_manifest_cannot_redirect_to_another_original(mixed):
    manifest = json.loads(mixed.second_manifest.read_text())
    manifest["session_id"] = mixed.origin["origin_session"]
    mixed.second_manifest.write_text(json.dumps(manifest))
    with pytest.raises(views.FaithSieveViewError, match="身份"):
        views.workflow_snapshot(mixed.run)


def test_missing_direct_original_manifest_never_recurses_through_source_lineage(mixed, monkeypatch):
    mixed.second_manifest.unlink()
    (mixed.second_workspace / PRIVATE).write_text("来源的 lineage 不允许读取")
    original = views._cached_judge
    lookups = []
    def cached(root_fd, run, key, role, record):
        lookups.append((run["attempt_id"], key))
        return original(root_fd, run, key, role, record)
    monkeypatch.setattr(views, "_cached_judge", cached)
    before = snapshot_files(mixed.root)
    stages = views.workflow_snapshot(mixed.run)["stages"]
    assert stages[0]["session_id"] == mixed.origin["origin_session"]
    assert stages[1]["session_id"] is None
    assert lookups == [(mixed.run["attempt_id"], KEY), (mixed.run["attempt_id"], SECOND_KEY)]
    assert mixed.source_calls == [SOURCE, SECOND_SOURCE]
    assert snapshot_files(mixed.root) == before
