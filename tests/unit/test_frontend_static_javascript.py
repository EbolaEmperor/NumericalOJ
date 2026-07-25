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
    "static/app/editor-semantic-tokens.js",
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


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_semantic_token_client_separates_editor_and_markdown_payloads():
    asset = ROOT / "static" / "app" / "editor-semantic-tokens.js"
    script = f"""
global.window = global;
const calls = [];
global.fetch = async function(url, options) {{
  calls.push({{url, options: options || {{}}}});
  if (String(url).includes("semantic-token-legend")) {{
    return {{
      ok: true,
      json: async function() {{
        return {{
          success: true,
          legend: {{tokenTypes: ["class"], tokenModifiers: []}}
        }};
      }}
    }};
  }}
  return {{
    ok: true,
    json: async function() {{
      return {{success: true, data: [0, 0, 3, 0, 0], result_id: "1:test"}};
    }}
  }};
}};
require({str(asset)!r});
(async function() {{
  await NumOJSemanticTokens.getLegend("cpp");
  await NumOJSemanticTokens.requestTokens({{
    context: "markdown",
    language: "cpp",
    source: "std::vector<int> values;"
  }});
  await NumOJSemanticTokens.requestTokens({{
    problemId: 42,
    language: "cpp",
    source: "int main() {{}}"
  }});
  const requests = calls
    .filter(function(call) {{ return call.options.method === "POST"; }})
    .map(function(call) {{ return JSON.parse(call.options.body); }});
  if (requests.length !== 2) process.exit(1);
  if (requests[0].context !== "markdown") process.exit(2);
  if (Object.prototype.hasOwnProperty.call(requests[0], "problem_id")) {{
    process.exit(3);
  }}
  if (requests[1].problem_id !== 42) process.exit(4);
  if (Object.prototype.hasOwnProperty.call(requests[1], "context")) {{
    process.exit(5);
  }}
}})().catch(function() {{ process.exit(6); }});
"""
    subprocess.run(
        [NODE, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_markdown_semantic_client_retries_busy_but_not_rate_limits():
    asset = ROOT / "static" / "app" / "editor-semantic-tokens.js"
    script = f"""
global.window = global;
Math.random = function() {{ return 0; }};
let mode = "busy";
let calls = 0;
global.fetch = async function() {{
  calls += 1;
  if (mode === "busy" && calls === 1) {{
    return {{
      ok: false,
      status: 429,
      headers: {{get: function() {{ return "0.001"; }}}},
      json: async function() {{
        return {{success: false, code: "result_pending", message: "pending"}};
      }}
    }};
  }}
  if (mode === "rate") {{
    return {{
      ok: false,
      status: 429,
      headers: {{get: function() {{ return "1"; }}}},
      json: async function() {{
        return {{success: false, code: "rate_limited", message: "limited"}};
      }}
    }};
  }}
  return {{
    ok: true,
    status: 200,
    json: async function() {{
      return {{success: true, data: [0, 0, 3, 0, 0]}};
    }}
  }};
}};
require({str(asset)!r});
(async function() {{
  await NumOJSemanticTokens.requestTokens({{
    context: "markdown",
    language: "cpp",
    source: "int value;"
  }});
  if (calls !== 2) process.exit(1);
  mode = "rate";
  calls = 0;
  try {{
    await NumOJSemanticTokens.requestTokens({{
      context: "markdown",
      language: "cpp",
      source: "int other;"
    }});
    process.exit(2);
  }} catch (error) {{
    if (error.code !== "rate_limited") process.exit(3);
    if (calls !== 1) process.exit(4);
  }}
}})().catch(function() {{ process.exit(5); }});
"""
    subprocess.run(
        [NODE, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )
