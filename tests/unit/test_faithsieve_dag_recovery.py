"""新协议失败预检只重放缓存，按冻结版本选择节点编排器。"""

import json

import pytest

from backend.oj_modules.ai.endpoints import LLMEndpointRequestError
from backend.oj_modules.faithsieve import recovery, workflow
from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.checkpoints import CheckpointStore
from backend.oj_modules.faithsieve.dependency_workflow import DependencyWorkflow
from backend.oj_modules.faithsieve.errors import FaithSieveEndpointError
from backend.oj_modules.faithsieve.runtime_snapshot import SNAPSHOT_FILENAME
from tests.unit.test_faithsieve_recovery import FILES, TARGET, run
from tests.unit.test_faithsieve_workflow import thinking_endpoint


@pytest.mark.parametrize("source_version", ["v2", "v1", "legacy"])
def test_v2_recovery_preview_uses_exact_new_request_and_never_calls_or_writes(tmp_path, run, source_version):
    snapshot = tmp_path / SNAPSHOT_FILENAME
    snapshot.write_text(json.dumps({"endpoint_id": 7, "initial_reasoning_effort": None}))
    snapshot.chmod(0o600)
    (tmp_path / "submission.pdf").write_bytes(b"%PDF-original")
    endpoint = thinking_endpoint(enabled=False)
    engine = DependencyWorkflow(endpoint=endpoint, verification_agent=None, workspace=tmp_path,
                                chat=lambda *_a, **_k: (_ for _ in ()).throw(LLMEndpointRequestError("端点连接失败", request_failure="connection")))
    for path, text in FILES.items():
        engine.store.write(path, text)
    request = {"problem_text": FILES["problem.md"], "pdf_path": "submission.pdf"}
    if source_version != "legacy":
        request["timeout_seconds"] = workflow.SOURCE_TIMEOUT_SECONDS
    if source_version == "v2":
        request["proof_graph_version"] = 2
    engine.checkpoints.put("source-extraction", request, state="completed", response={"status": "ok", "text": FILES[workflow.SOURCE]})
    with pytest.raises(FaithSieveEndpointError):
        engine._invoke("decomposer", files=FILES)
    before = {p.relative_to(tmp_path).as_posix(): (p.read_bytes(), p.stat().st_mtime_ns) for p in tmp_path.rglob("*") if p.is_file()}
    recovery.validate_recovery_inputs(tmp_path, run, problem_text=FILES["problem.md"], submission_pdf=b"%PDF-original", endpoint=endpoint)
    after = {p.relative_to(tmp_path).as_posix(): (p.read_bytes(), p.stat().st_mtime_ns) for p in tmp_path.rglob("*") if p.is_file()}
    assert after == before
    target = CheckpointStore(tmp_path)._read_record(TARGET, strict=True)[0]
    assert target["request"]["proof_graph_version"] == 2


def test_unknown_frozen_graph_version_fails_closed_before_recovery(tmp_path, run):
    engine = DependencyWorkflow(endpoint=thinking_endpoint(enabled=False), verification_agent=None, workspace=tmp_path,
                                chat=lambda *_a, **_k: (_ for _ in ()).throw(LLMEndpointRequestError("连接失败", request_failure="connection")))
    with pytest.raises(FaithSieveEndpointError):
        engine._invoke("decomposer", files=FILES)
    (tmp_path / "submission.pdf").write_bytes(b"%PDF-original")
    path = tmp_path / "faithsieve-work/checkpoints" / (TARGET + ".json")
    target = json.loads(path.read_text())
    target["request"]["proof_graph_version"] = "2"
    path.write_text(json.dumps(target))
    before = path.read_bytes()
    with pytest.raises((FaithSieveProtocolError, recovery.FaithSieveRecoveryError), match="版本"):
        recovery.validate_recovery_inputs(tmp_path, run, problem_text=FILES["problem.md"], submission_pdf=b"%PDF-original",
                                          endpoint=thinking_endpoint(enabled=False))
    assert path.read_bytes() == before
