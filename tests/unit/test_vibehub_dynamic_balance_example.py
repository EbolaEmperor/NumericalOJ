"""动态平衡术示例的教育状态、服务边界与成绩反馈。"""

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "vibehub_examples" / "dynamic-balance"


@pytest.fixture
def balance():
    spec = importlib.util.spec_from_file_location("dynamic_balance_example", EXAMPLE / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_manifest_declares_separate_internal_education_socket_and_platform_executor():
    manifest = json.loads((EXAMPLE / "vibehub.json").read_text())
    assert manifest["kind"] == "edu"
    assert manifest["education"] == {
        "protocol": "vibehub-edu/1",
        "socket_path": "/run/vibehub/edu.sock",
        "executor": "cpp-heap-median-v1",
    }
    assert (EXAMPLE / manifest["cover_image"]).is_file()


def test_start_is_deterministic_and_accepts_the_platform_practice_sequence(balance):
    context = {"challenge_seed": "example", "parameters": {"inputs": [7, 3, 10]}}
    initial = balance.start(context)
    assert initial == balance.start(context)
    assert initial["view"]["inputs"] == [7, 3, 10]
    assert "int step(int x)" in initial["view"]["source"]
    assert "user_id" not in initial["view"]


def test_action_cannot_supply_its_own_execution_result(balance):
    state = balance.start({"challenge_seed": "example"})["state"]
    with pytest.raises(ValueError, match="可信"):
        balance.step({}, state, {"type": "run_code", "source": "int step(int x){return x;}", "execution": {"passed": 100}})
    execution = {"compiled": True, "rounds": [], "passed": 0, "total": 20}
    updated = balance.step({"execution": execution}, state, {"type": "run_code", "source": "int step(int x){return x;}"})
    assert updated["state"]["execution"] == execution
    assert updated["state"]["inputs"] == state["inputs"]
    assert state["execution"] is None


def test_grading_uses_only_frozen_platform_execution_and_keeps_hidden_cases_private(balance):
    execution = {"compiled": True, "passed": 17, "total": 20, "rounds": [{"x": -999, "expected": 12}]}
    actions = [{"action": {"type": "fake_score", "score": 100}},
               {"action": {"type": "run_code", "source": "int step(int x){return x;}"}}]
    result = balance.grade({"execution": execution}, actions)
    assert result["score_bp"] == 8500
    assert result["metrics"] == {"passed_rounds": 17, "total_rounds": 20}
    assert "-999" not in json.dumps(result)
    assert result["verdict"] == "failed"
    result = balance.grade({"execution": {"compiled": False, "error": "编译错误", "passed": 0, "total": 20}}, actions)
    assert result["score_bp"] == 0
    assert "编译错误" in result["feedback"]


def test_demo_displays_conveyor_and_real_heap_playback_without_executing_cpp_itself():
    source = (EXAMPLE / "app.py").read_text()
    assert "subprocess" not in source
    assert "exec(" not in source
    html = (EXAMPLE / "static" / "index.html").read_text()
    for item in ('id="conveyor"', 'id="heapA"', 'id="heapB"', 'id="runButton"', 'id="submitButton"'):
        assert item in html
    script = (EXAMPLE / "static" / "app.js").read_text()
    assert "if (!result.passed" in script
    assert "上浮" in script and "下沉" in script
    assert "action: { type: 'run_code', source }" in script
    assert "score: 100" not in script
