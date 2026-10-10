"""检查对象路由元数据的 Markdown 样式与明确性边界。"""

from pathlib import Path

import pytest

from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve import workflow


FIXTURE = Path(__file__).parent / "fixtures/faithsieve/E10-O2-check.md"


@pytest.mark.parametrize("route", ["lean", "numeric"])
@pytest.mark.parametrize("value", ["{route}", "`{route}`", "``{route}``", "*{route}*", "**{route}**", "_{route}_", "__{route}__", "***`{route}`***"])
@pytest.mark.parametrize("label", ["route", "**route**", "`route`"])
def test_route_metadata_accepts_inline_styles_and_preserves_control(route, value, label):
    text = f"# 检查对象\n\n- {label}: {value.format(route=route)}\n\n原义务与 source mapping。"
    assert workflow._check_object_route(text, route) == route


@pytest.mark.parametrize("text, control", [
    ("route=lean", "lean"),
    ("Route: LEAN", "lean"),
    ("+ route = **numeric**", "numeric"),
    ("```text\nroute: numeric\n```\n- route: `lean`", "lean"),
    ("~~~text\nroute: numeric\n~~~\n- route: *lean*", "lean"),
])
def test_route_metadata_accepts_standalone_declaration(text, control):
    assert workflow._check_object_route(text, control) == control


@pytest.mark.parametrize("text, control", [
    ("没有 route 元数据。", "lean"),
    ("说明：示例 route=lean", "lean"),
    ("> route: lean", "lean"),
    ("    route: lean", "lean"),
    ("\troute: lean", "lean"),
    (" \troute: lean", "lean"),
    ("<!--\nroute: lean\n-->", "lean"),
    ("<!-- closed --> <!--\nroute: lean\n-->", "lean"),
    ("<!-- route: lean -->", "lean"),
    ("```text\nroute: lean\n```", "lean"),
    ("~~~text\nroute: lean\n~~~", "lean"),
    ("- route: **lean*", "lean"),
    ("- route: `lean", "lean"),
    ("route: " + "*" * 100000 + "lean" + "*" * 100000, "lean"),
    ("route: " + "`" * 100000 + "lean" + "`" * 100000, "lean"),
    ("route: lean-ish", "lean"),
    ("route: lean 后面是说明", "lean"),
    ("route: lean\nroute: numeric", "lean"),
    ("route: lean\n- route: unknown", "lean"),
    ("route: lean\n- route: **lean**", "lean"),
    ("route: lean", "numeric"),
    ("route: numeric", "lean"),
    ("route: lean", "LEAN"),
    ("route: lean", None),
    ("route: lean", ["lean"]),
])
def test_route_metadata_rejects_missing_conflicting_or_ambiguous_declarations(text, control):
    with pytest.raises(FaithSieveProtocolError, match="路径|route"):
        workflow._check_object_route(text, control)


def test_complete_actual_check_object_snapshot_routes_to_lean_without_rewriting(tmp_path, monkeypatch):
    # 只重放公开论文测试稿生成的检查对象；不复用其数学结论或执行证据。
    original = FIXTURE.read_bytes()
    text = original.decode("utf-8")
    assert len(original) == 7915
    assert "- route: **lean**" in text
    engine = workflow.FaithSieveWorkflow(endpoint=None, verification_agent=None, workspace=tmp_path)
    identifier = "E10-O2"
    obligation = {"id": identifier, "path": "faithsieve-work/obligations/E10/E10-O2.md", "depends_on": []}
    check_path = "faithsieve-work/formal/E10-O2-check.md"
    engine.store.write(check_path, text)
    monkeypatch.setattr(engine, "_obligation_context", lambda *_args: {})
    monkeypatch.setattr(engine, "_invoke", lambda role, **_kwargs: workflow.RoleOutput(
        {"status": "ok", "artifact": check_path}, {"route": "lean"}, {}, "check-snapshot",
    ) if role == "check-object-generator" else pytest.fail("不能改为数值验证"))
    branches = []

    def stop_before_any_lean_call(_identifier, _path, branch, **_kwargs):
        branches.append(branch)
        return {"status": "passed", "route": "lean", "branch": branch}

    monkeypatch.setattr(engine, "_verify_lean_branch", stop_before_any_lean_call)
    assert engine._verify_obligation(obligation) == "passed"
    assert branches == ["original"]
    assert engine.store.read(check_path).encode("utf-8") == original
    assert FIXTURE.read_bytes() == original
