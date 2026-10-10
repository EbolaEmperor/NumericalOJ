"""冻结原稿复核意见在完整缓存前缀后派真实修图对，不制造数学结果。"""

from collections import Counter
import copy
from datetime import datetime
import json
import os

import pytest

from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.dependency_workflow import NODE_VERIFICATION
from backend.oj_modules.faithsieve.graph_context_revision import GRAPH_CONTEXT_REVISION_KEY
from backend.oj_modules.faithsieve.graph_repair_policy import GRAPH_REPAIR_POLICY_KEY
from backend.oj_modules.faithsieve import views
from backend.oj_modules.faithsieve import judge, recovery
from backend.oj_modules.faithsieve.image_workflow import ImageWorkflow, freeze_rendered_images, image_render_request
from backend.oj_modules.faithsieve.runtime_snapshot import SNAPSHOT_FILENAME
from backend.oj_modules.faithsieve.workflow import TREE, WORK
from tests.unit.test_faithsieve_image_repair import RepairScript, checkpoint_bytes, make_engine
from tests.unit.test_faithsieve_image_workflow import PNG, Pending, rendered
from tests.unit.test_faithsieve_input_transport import decode_input_message


REVIEW = "原稿的变换对象未忠实进入当前命题，请核对完整图片并修正该节点及直接使用它的命题。"


class ContextScript(RepairScript):
    def __init__(self, root):
        super().__init__(root, defect=False)
        self.events = []
        self.pause_repair_audit = False
        self.paused_request = None

    def chat(self, endpoint, messages, **options):
        header = messages[0]["content"].splitlines()[0]
        self.events.append(("pure", header))
        if header == "# Tree auditor" and self.builder_count > 1 and self.pause_repair_audit:
            self.pause_repair_audit = False
            self.paused_request = copy.deepcopy((messages, options))
            raise Pending("repair-auditor")
        return super().chat(endpoint, messages, **options)

    def run_role(self, **request):
        node = request["expected_result_path"].rsplit("/", 1)[-1].split("-local-verifier")[0]
        self.events.append(("native", node))
        return super().run_role(**request)


def frozen_prefix(root):
    script = ContextScript(root)
    engine = make_engine(root, script)
    verify = engine._verify_node

    def stop_before_uncached_node(identifier, obligation):
        if identifier == "N2":
            raise Pending("complete-prefix")
        return verify(identifier, obligation)

    engine._verify_node = stop_before_uncached_node
    with pytest.raises(Pending, match="complete-prefix"):
        engine.run()
    engine._verify_node = verify
    assert engine._role_counter == 9
    assert Counter(call["node"] for call in script.native) == {"N5": 1, "N4": 1, "N3": 1}
    assert not (engine.checkpoints.directory / "role-000010-attempt-1.json").exists()
    original = checkpoint_bytes(engine)
    assert all(json.loads(raw)["state"] == "completed" for raw in original.values())
    return engine, script, original


def add_instruction(engine, *, boundary=9, affected=("N3", "N4")):
    request = {"version": 1, "after_role_counter": boundary,
               "affected_node_ids": list(affected), "report": REVIEW}
    engine.checkpoints.put(GRAPH_CONTEXT_REVISION_KEY, request, state="completed", response={"accepted": True})
    return request


def unchanged_prefix(engine, original):
    assert all((engine.checkpoints.directory / filename).read_bytes() == raw for filename, raw in original.items())


def roles_after_boundary(engine, boundary=9):
    records = engine.checkpoints.records()
    return [(key, record) for key, record in sorted(records.items())
            if key.startswith("role-") and int(key.split("-")[1]) > boundary]


def test_context_revision_runs_real_pair_before_uncached_judge_and_preserves_exact_cache(tmp_path):
    engine, script, original = frozen_prefix(tmp_path)
    request = add_instruction(engine)
    # 标签和依赖编号的变化不改变局部蕴含，也不能触发额外重验。
    script.repaired_graph["nodes"][1]["label"] = "相同数学命题的新标签"
    script.repaired_graph["edges"][3]["id"] = "D40"
    before = len(script.events)
    result = engine.run()
    assert result["verdict"] == "correct"
    assert script.events[before:before + 3] == [
        ("pure", "# Tree builder"), ("pure", "# Tree auditor"), ("pure", "# Node selector"),
    ]
    new = roles_after_boundary(engine)
    assert [(key, saved["request"]["role"]) for key, saved in new[:3]] == [
        ("role-000010-attempt-1", "tree-builder"),
        ("role-000011-attempt-1", "tree-auditor"),
        ("role-000012-attempt-1", "node-selector"),
    ]
    builder = new[0][1]["request"]
    assert builder["revision_report"] == request["report"]
    assert json.loads(builder["files"][f"{WORK}/graphs/context-revision-9-previous.json"]) == script.initial_graph
    assert builder["files"][f"{WORK}/review/context-revision-9.md"] == REVIEW
    assert len(builder["messages"][1]["content"]) == 3
    assert Counter(call["node"] for call in script.native) == {"N5": 1, "N4": 2, "N3": 2, "N2": 1}
    assert script.defect_count == 0
    old_consumer, new_consumer = [call["context"] for call in script.native if call["node"] == "N4"]
    assert old_consumer["premises"][0]["statement"] != new_consumer["premises"][0]["statement"]
    assert engine.store.read_json(TREE) == script.repaired_graph
    assert engine.store.read_json(NODE_VERIFICATION)["targets_established"] is True
    unchanged_prefix(engine, original)
    frozen = checkpoint_bytes(engine)
    calls = len(script.events)
    assert engine.run() == result
    assert len(script.events) == calls
    assert checkpoint_bytes(engine) == frozen


def test_host_control_is_not_a_native_input_or_public_stage(tmp_path):
    engine, script, _original = frozen_prefix(tmp_path)
    add_instruction(engine)
    assert engine.run()["verdict"] == "correct"
    for call in script.native:
        request = call["request"]
        assert not {"after_role_counter", "affected_node_ids", "graph_context_revision"}.intersection(request)
        assert REVIEW not in json.dumps(request, ensure_ascii=False, default=lambda _value: "<binary>")
        assert GRAPH_CONTEXT_REVISION_KEY not in json.dumps(request, ensure_ascii=False, default=lambda _value: "<binary>")
        assert not any("context-revision" in path for path in request["files"])
        assert request["files"]["source-pages/page-1.png"] == PNG + b"\x01"
        assert request["files"]["source-pages/page-2.png"] == PNG + b"\x02"
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        snapshot = views._snapshot(fd, {"attempt_id": "a" * 32, "execution_mode": "workflow"})
    finally:
        os.close(fd)
    assert snapshot["stages"]
    assert not any(stage["key"] in {GRAPH_CONTEXT_REVISION_KEY, GRAPH_REPAIR_POLICY_KEY}
                   for stage in snapshot["stages"])
    assert GRAPH_CONTEXT_REVISION_KEY not in json.dumps(snapshot, ensure_ascii=False)
    assert not any("context-revision" in artifact["path"] for artifact in snapshot["artifacts"])


def test_every_affected_local_context_must_change_before_more_verification(tmp_path):
    engine, script, original = frozen_prefix(tmp_path)
    add_instruction(engine, affected=("N3", "N5"))
    before = len(script.native)
    result = engine.run()
    assert result["verdict"] == "inconclusive" and "没有改变指定节点" in result["comment"]
    assert "N5" in result["comment"]
    assert len(script.native) == before
    assert [saved["request"]["role"] for _key, saved in roles_after_boundary(engine)] == ["tree-builder", "tree-auditor"]
    assert not (engine.checkpoints.directory / "final-scoring.json").exists()
    unchanged_prefix(engine, original)


@pytest.mark.parametrize("affected", [("N99",), ("N1",)])
def test_unknown_or_given_node_does_not_start_repair(tmp_path, affected):
    engine, script, original = frozen_prefix(tmp_path)
    add_instruction(engine, affected=affected)
    before = len(script.events)
    result = engine.run()
    assert result["verdict"] == "inconclusive"
    assert len(script.events) == before
    assert not roles_after_boundary(engine)
    unchanged_prefix(engine, original)


def test_late_boundary_is_rejected_without_new_model_or_native_calls(tmp_path):
    engine, script, original = frozen_prefix(tmp_path)
    add_instruction(engine, boundary=8)
    before = len(script.events)
    result = engine.run()
    assert result["verdict"] == "inconclusive" and "缓存边界" in result["comment"]
    assert len(script.events) == before
    assert not roles_after_boundary(engine)
    unchanged_prefix(engine, original)


@pytest.mark.parametrize("boundary", [10, 99])
def test_unreached_boundary_cannot_create_new_math_to_fill_the_prefix(tmp_path, boundary):
    engine, script, original = frozen_prefix(tmp_path)
    add_instruction(engine, boundary=boundary)
    before = len(script.events)
    result = engine.run()
    assert result["verdict"] == "inconclusive"
    assert len(script.events) == before
    assert not roles_after_boundary(engine)
    unchanged_prefix(engine, original)


def test_pending_repair_auditor_reentry_preserves_prefix_and_completed_builder(tmp_path):
    engine, script, original = frozen_prefix(tmp_path)
    add_instruction(engine)
    script.pause_repair_audit = True
    native_count = len(script.native)
    with pytest.raises(Pending, match="repair-auditor"):
        engine.run()
    assert len(script.native) == native_count
    assert script.builder_count == 2
    repair = engine.checkpoints.directory / "role-000010-attempt-1.json"
    repair_bytes = repair.read_bytes()
    pending_path = engine.checkpoints.directory / "role-000011-attempt-1.json"
    pending = json.loads(pending_path.read_text())
    assert pending["state"] == "pending" and pending["request"]["role"] == "tree-auditor"
    unchanged_prefix(engine, original)
    before = len(script.events)
    assert engine.run()["verdict"] == "correct"
    assert script.events[before] == ("pure", "# Tree auditor")
    completed_audit = next(call for call in reversed(script.pure) if call["role"] == "tree-auditor")
    assert (completed_audit["messages"], completed_audit["options"]) == script.paused_request
    assert script.builder_count == 2 and repair.read_bytes() == repair_bytes
    assert Counter(call["node"] for call in script.native) == {"N5": 1, "N4": 2, "N3": 2, "N2": 1}
    unchanged_prefix(engine, original)


def test_repair_auditor_has_only_canonical_graph_and_full_original_images(tmp_path):
    engine, script, _original = frozen_prefix(tmp_path)
    add_instruction(engine)
    assert engine.run()["verdict"] == "correct"
    auditor = next(call for call in script.pure if call["role"] == "tree-auditor"
                   and json.loads(decode_input_message(call["messages"][1]["content"][0]["text"])["input_files"][TREE]) == script.repaired_graph)
    content = auditor["messages"][1]["content"]
    files = decode_input_message(content[0]["text"])["input_files"]
    assert set(files) == {"problem.md", "pages.json", TREE}
    assert REVIEW not in json.dumps(auditor["messages"], ensure_ascii=False)
    assert len(content) == 3 and all(block["type"] == "image_url" for block in content[1:])


@pytest.mark.parametrize("drift", [None, "original_prompt", "repair_image"])
def test_recovery_preview_reads_host_context_through_standard_get_and_replays_actual_prefix(tmp_path, monkeypatch, drift):
    """实际 PreviewStore 必须登记宿主意见，再逐角色核对冻结输入，而非列举后提前 ready。"""
    engine, script, _original = frozen_prefix(tmp_path)
    problem, pdf = engine.store.read("problem.md"), b"%PDF-frozen-context-review"
    engine.checkpoints.preserve_pdf(pdf)
    engine.checkpoints.put("image-render", image_render_request(problem), state="completed",
                           response=freeze_rendered_images(rendered()))
    snapshot = tmp_path / SNAPSHOT_FILENAME
    snapshot.write_text(json.dumps({"endpoint_id": engine.endpoint["id"], "initial_reasoning_effort": None}))
    snapshot.chmod(0o600)
    add_instruction(engine)
    script.pending = "N4"
    with pytest.raises(Pending, match="N4"):
        engine.run()
    target = "role-000013-attempt-1"
    run = {"attempt_id": "a" * 32, "submission_id": 12, "problem_id": 4,
           "endpoint_id": engine.endpoint["id"], "harness": "pi", "execution_mode": "workflow",
           "requested_by": "teacher", "session_id": "faithsieve-" + "a" * 32,
           "started_at": datetime(2026, 10, 10, 8, 32, 49), "status": "failed",
           "elapsed_seconds": 1200, "result_json": None}

    def inspect(_workspace, actual_run, key, _record):
        assert key == target
        task = f"ft-{run['attempt_id']}-{target}"
        return {"kind": "native_timeout", "session_id": f"fs-{run['attempt_id']}-{target}",
                "failed_task_id": task, "original_timeout_seconds": 600,
                "continuation_task_id": task + "-c1",
                "continuation_timeout_seconds": 7200 - actual_run["elapsed_seconds"],
                "continuation_prompt": "继续同一完整局部验证，原始图片和命题保持只读。"}

    monkeypatch.setattr(judge, "inspect_native_timeout", inspect)
    permission = recovery.prepare_recovery(tmp_path, run, "admin")
    assert permission["target_key"] == target
    script.pending = "N3"
    with pytest.raises(Pending, match="N3"):
        engine.run()
    monkeypatch.setattr(judge, "inspect_completed_native", lambda *_args: None)
    if drift is not None:
        key = "role-000001-attempt-1" if drift == "original_prompt" else "role-000010-attempt-1"
        path = engine.checkpoints.directory / f"{key}.json"
        saved = json.loads(path.read_text())
        if drift == "original_prompt":
            saved["request"]["messages"][0]["content"] += "冻结后另行加入的提示。"
        else:
            saved["request"]["messages"][1]["content"][1]["image_url"]["url"] += "AAAA"
        path.write_text(json.dumps(saved, ensure_ascii=False))
    replayed_roles = []
    original_invoke = ImageWorkflow._invoke

    def track_invoke(self, role, **request):
        replayed_roles.append(role)
        return original_invoke(self, role, **request)

    monkeypatch.setattr(ImageWorkflow, "_invoke", track_invoke)
    before = {path.relative_to(tmp_path).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
              for path in tmp_path.rglob("*") if path.is_file()}
    calls = len(script.pure), len(script.native), len(script.events)
    options = {"problem_text": problem, "submission_pdf": pdf, "endpoint": engine.endpoint, "target_key": target}
    if drift is None:
        recovery.validate_recovery_inputs(tmp_path, {**run, "status": "running", "elapsed_seconds": 2400}, **options)
        assert replayed_roles[:3] == ["tree-builder", "tree-auditor", "node-selector"]
        assert replayed_roles.count("tree-builder") == 2 and replayed_roles.count("tree-auditor") == 2
    else:
        with pytest.raises((recovery.FaithSieveRecoveryError, FaithSieveProtocolError)):
            recovery.validate_recovery_inputs(tmp_path, {**run, "status": "running", "elapsed_seconds": 2400}, **options)
        assert replayed_roles and replayed_roles[0] == "tree-builder"
    assert (len(script.pure), len(script.native), len(script.events)) == calls
    assert {path.relative_to(tmp_path).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in tmp_path.rglob("*") if path.is_file()} == before
