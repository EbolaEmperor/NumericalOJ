"""通用职责不携带样题内容，模板更新不改变已冻结的数学输入。"""

from copy import deepcopy
import json
from pathlib import Path
import re

import pytest

from backend.oj_modules.faithsieve import image_workflow, judge, prompts
from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.workflow import WORK
from tests.unit.test_faithsieve_image_workflow import Pending, Script, seed


ROOT = Path(__file__).resolve().parents[2]
OPTIONS = {"node_selection_version": 1, "verification_audit_version": 1,
           "verification_method_version": 1, "external_results_version": 1}
# 此前被误写入通用模板的样题内容；仅检查职责，不限制真实题面和原稿。
TASK_SPECIFIC = re.compile(
    r"Hilbert|Fourier|Stieltjes|有界变差|概率|随机事件|有限网格|有限参数集合|有限抽样|"
    r"全域反例|代理族|特殊族|一般族|几乎处处|严格正性|非零条件|平方模|范数|"
    r"积分变量|求和指标|端点约定|集中界|一致界|希腊字母|有理数"
)
RESOURCES = sorted([
    *(ROOT / "backend/oj_modules/faithsieve").rglob("*.md"),
    *(ROOT / "skills/faithsieve").rglob("*.md"),
    ROOT / "docs/faithsieve/README.md",
])


@pytest.mark.parametrize("path", RESOURCES, ids=lambda path: str(path.relative_to(ROOT)))
def test_prompt_resources_do_not_contain_sample_specific_rules(path):
    assert TASK_SPECIFIC.search(path.read_text(encoding="utf-8")) is None


@pytest.mark.parametrize("role", sorted(prompts.IMAGE_ROLE_NAMES))
def test_full_current_request_instructions_are_task_independent(role):
    prompt = prompts.render_image_role_prompt(role, {"node_id": "N4"}, **OPTIONS)
    assert TASK_SPECIFIC.search(prompt) is None
    if role == "local-verifier":
        native = judge._role_instruction(role, prompt, f"{WORK}/results/N4-local-verifier.json", 3,
                                         local_diagnostic_version=1, external_results_version=1)
        assert TASK_SPECIFIC.search(native) is None
        assert "FaithSieveProof" in native and "graph_defect" in native


def test_continuation_and_generated_local_contract_are_task_independent(tmp_path):
    assert TASK_SPECIFIC.search(judge._continuation_prompt("result.json", external_results_version=1)) is None
    script = Script(tmp_path)
    script.pending = "N4"
    engine = seed(tmp_path, script)
    with pytest.raises(Pending):
        engine.run()
    path = f"{WORK}/obligations/N4/N4-O1.md"
    local = json.loads(script.native[-1]["files"][path])
    assert TASK_SPECIFIC.search(local["verification_contract"]) is None
    assert local["node"]["id"] == "N4"
    assert [node["id"] for node in local["premises"]] == ["N2", "N3"]


def test_template_update_replays_frozen_calls_and_cleans_new_calls(tmp_path, monkeypatch):
    render = image_workflow.render_image_role_prompt
    fixed_obligation = image_workflow.ImageWorkflow._fixed_obligation

    def old_obligation(engine, identifier):
        obligation = fixed_obligation(engine, identifier)
        value = engine.store.read_json(obligation["path"])
        value["verification_contract"] += "旧版局部职责说明"
        engine.store.write(obligation["path"], json.dumps(value, ensure_ascii=False, indent=2))
        return obligation

    monkeypatch.setattr(image_workflow, "render_image_role_prompt",
                        lambda *args, **kwargs: render(*args, **kwargs) + "\n旧版通用职责说明")
    monkeypatch.setattr(image_workflow.ImageWorkflow, "_fixed_obligation", old_obligation)
    script = Script(tmp_path)
    script.pending = "N4"
    engine = seed(tmp_path, script)
    with pytest.raises(Pending):
        engine.run()
    pending = deepcopy(script.native[-1])
    completed = {path.name: path.read_bytes() for path in engine.checkpoints.directory.glob("*.json")
                 if json.loads(path.read_bytes())["state"] == "completed"}
    calls = len(script.pure)
    monkeypatch.setattr(image_workflow, "render_image_role_prompt", render)
    monkeypatch.setattr(image_workflow.ImageWorkflow, "_fixed_obligation", fixed_obligation)
    assert seed(tmp_path, script).run()["verdict"] == "correct"
    assert script.native[1] == pending
    assert all("旧版通用职责说明" not in messages[0]["content"]
               for role, messages, _options in script.pure[calls:])
    assert all((engine.checkpoints.directory / name).read_bytes() == data
               for name, data in completed.items())


def test_role_retry_cannot_adopt_a_different_frozen_responsibility(tmp_path):
    script = Script(tmp_path)
    script.pending = "N4"
    engine = seed(tmp_path, script)
    with pytest.raises(Pending):
        engine.run()
    request = next(value["request"] for value in engine.checkpoints.read_records().values()
                   if value["request"]["role"] == "local-verifier")
    changed = deepcopy(request)
    changed["prompt"] += "\n不同的验证职责"
    changed["agent_prompt"] = changed["agent_prompt"].replace(request["prompt"], changed["prompt"], 1)
    key = f"role-{engine._role_counter:06d}-attempt-2"
    engine.checkpoints.put(key, changed, state="pending")
    saved = engine.checkpoints._path(key).read_bytes()
    with pytest.raises(FaithSieveProtocolError, match="冻结职责不一致"):
        engine._preserve_frozen_role_prompt(key, request, original_prompt=request["prompt"])
    assert engine.checkpoints._path(key).read_bytes() == saved


@pytest.mark.parametrize("field", ["messages", "agent_prompt", "images", "files", "parameters",
                                  "endpoint", "call_options", "external_results_version"])
def test_template_replay_still_rejects_changed_inputs_and_inconsistent_messages(tmp_path, field):
    script = Script(tmp_path)
    script.pending = "N4"
    engine = seed(tmp_path, script)
    with pytest.raises(Pending):
        engine.run()
    records = engine.checkpoints.read_records()
    key = next(key for key, value in records.items() if value["request"]["role"] ==
               ("tree-builder" if field in {"messages", "call_options"} else "local-verifier"))
    path = engine.checkpoints._path(key)
    record = deepcopy(records[key])
    request = record["request"]
    if field == "messages":
        request["messages"][0]["content"] += "\n未保存到 prompt 的额外职责"
    elif field == "agent_prompt":
        request[field] += "\n额外条件"
    elif field == "external_results_version":
        request[field] = True
    elif field == "files":
        request[field]["problem.md"] += "额外条件"
    else:
        request[field]["changed"] = "不同输入"
    path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
    saved = path.read_bytes()
    before = len(script.pure), len(script.native)
    assert seed(tmp_path, script).run()["verdict"] == "inconclusive"
    assert (len(script.pure), len(script.native)) == before
    assert path.read_bytes() == saved


def test_frozen_obligation_keeps_its_instruction_but_checks_current_propositions(tmp_path):
    script = Script(tmp_path)
    script.pending = "N4"
    engine = seed(tmp_path, script)
    with pytest.raises(Pending):
        engine.run()
    record = next(value for value in engine.checkpoints.read_records().values()
                  if value["request"]["role"] == "local-verifier")
    obligation = f"{WORK}/obligations/N4/N4-O1.md"
    frozen = record["request"]["files"][obligation]
    engine._role_counter -= 1
    engine._fixed_obligation("N4")
    assert engine.store.read(obligation) == frozen
    engine.node_contexts["N4"]["premises"][0]["statement"] += "更强的前提"
    with pytest.raises(FaithSieveProtocolError, match="完整命题不一致"):
        engine._fixed_obligation("N4")
    assert engine.store.read(obligation) == frozen
