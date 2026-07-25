"""无需浏览器状态的前端静态 JavaScript 契约。"""

import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
NODE = shutil.which("node")
JAVASCRIPT_ASSETS = (
    "static/app/arc-agi-3-catalog.js",
    "static/app/arc-agi-3.js",
    "static/app/class-picker.js",
    "static/app/choice-picker.js",
    "static/app/markdown-rendering.js",
    "static/app/forum.js",
    "static/app/ranking/endpoints.js",
    "static/app/ranking/rules-editor.js",
    "static/app/ranking/topology.js",
)


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
@pytest.mark.parametrize("relative_path", JAVASCRIPT_ASSETS)
def test_frontend_javascript_has_valid_syntax(relative_path):
    subprocess.run(
        [NODE, "--check", str(ROOT / relative_path)],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_rule_topology_factory_is_deterministic_and_rejects_cycles():
    asset = ROOT / "static" / "app" / "ranking" / "topology.js"
    script = f"""
global.window = global;
require({str(asset)!r});
const topology = RuleTopology.create({{
  nodeWidth: 168,
  nodeHeight: 100,
  marginX: 24,
  marginY: 20,
  columnGap: 88,
  rowGap: 80,
  slotPadding: 42,
  maxSlotStep: 17
}});
const rules = [
  {{rule_id: 1, dependencies: []}},
  {{rule_id: 2, dependencies: [1]}},
  {{rule_id: 3, dependencies: [1]}}
];
const layout = topology.layout(rules);
if (!layout || layout.width !== 472 || layout.height !== 320) process.exit(1);
if (layout.positions[1].x !== 24 || layout.positions[1].y !== 20) process.exit(2);
if (layout.positions[2].y !== 200 || layout.positions[3].y !== 200) process.exit(3);
const routes = topology.buildRoutes([{{from: 1, to: 2}}, {{from: 1, to: 3}}], layout);
for (const key of ['1:2', '1:3']) {{
  if (!routes[key] || !topology.edgePath(routes[key]).startsWith('M ')) process.exit(4);
}}
const cycle = topology.layout([
  {{rule_id: 1, dependencies: [2]}},
  {{rule_id: 2, dependencies: [1]}}
]);
if (cycle !== null) process.exit(5);
"""
    subprocess.run(
        [NODE, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )
