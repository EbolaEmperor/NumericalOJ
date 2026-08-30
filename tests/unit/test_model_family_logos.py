"""模型家族识别、图标资产与共享渲染入口的前端契约。"""

import json
import re
import shutil
import subprocess
from pathlib import Path
from xml.etree import ElementTree

import pytest


ROOT = Path(__file__).resolve().parents[2]
NODE = shutil.which("node")

MODEL_FAMILY_JAVASCRIPT = ROOT / "frontend" / "public" / "static" / "app" / "model-family.js"
MODEL_FAMILY_STYLESHEET = ROOT / "frontend" / "public" / "static" / "app" / "model-family-logos.css"
MODEL_FAMILY_ASSET_DIRECTORY = ROOT / "frontend" / "public" / "static" / "app" / "model-family-logos"

MODEL_FAMILIES = frozenset(
    {
        "ai21",
        "amazon",
        "baai",
        "baichuan",
        "baidu",
        "claude",
        "cohere",
        "deepseek",
        "doubao",
        "gemini",
        "gemma",
        "glm",
        "grok",
        "hunyuan",
        "internlm",
        "jina",
        "kimi",
        "llama",
        "microsoft",
        "minimax",
        "mistral",
        "nvidia",
        "openai",
        "perplexity",
        "qwen",
        "stepfun",
        "tii",
        "voyage",
        "yi",
    }
)


@pytest.mark.skipif(NODE is None, reason="当前环境未安装 Node.js")
def test_model_family_detection_and_icon_class_contract():
    """关键词识别应稳定处理大小写、多家族名称、边界和未知模型。"""

    cases = [
        # 用户要求覆盖的十个主要家族，以及 Claude 的系列别名。
        ("GpT-4.1", "openai"),
        ("CLAUDE-3.7-SONNET", "claude"),
        ("anthropic/Opus-4", "claude"),
        ("HaIkU-3.5", "claude"),
        ("Google/GeMiNi-2.5-Pro", "gemini"),
        ("xAI/GROK-4", "grok"),
        ("Alibaba/QwEn3-235B", "qwen"),
        ("DouBao-Pro-32K", "doubao"),
        ("Seed-1.6-Thinking", "doubao"),
        ("DeepSeek-V3", "deepseek"),
        ("MiniMax-M1", "minimax"),
        ("Zhipu/GLM-4.5", "glm"),
        ("Qwen2.5-72B-Instruct-GPTQ-Int4", "qwen"),
        ("Llama-3.1-70B-GPTQ", "llama"),
        ("Mistral-7B-GPTQ", "mistral"),
        ("Moonshot/KiMi-K2", "kimi"),
        # 多家族字符串按主模型而非蒸馏目标识别。
        ("DeepSeek-R1-Distill-Qwen-32B", "deepseek"),
        ("Llama-Nemotron-Ultra-253B", "nvidia"),
        ("ollama/qwen2.5-coder", "qwen"),
        # 常见扩展家族。
        ("google/gemma-3", "gemma"),
        ("meta-llama/Llama-4-Maverick", "llama"),
        ("mistralai/Mixtral-8x22B", "mistral"),
        ("Cohere/Command-R-Plus", "cohere"),
        ("Microsoft/Phi-4", "microsoft"),
        ("AWS/Nova-Pro", "amazon"),
        ("Baidu/ERNIE-4.5", "baidu"),
        ("Tencent/Hunyuan-T1", "hunyuan"),
        ("Baichuan-4", "baichuan"),
        ("01-ai/Yi-Large", "yi"),
        ("AI21/Jamba-1.5", "ai21"),
        ("Perplexity/Sonar-Pro", "perplexity"),
        ("StepFun/Step-3", "stepfun"),
        ("InternLM-3", "internlm"),
        ("BAAI/bge-m3", "baai"),
        ("Jina-Embeddings-v3", "jina"),
        ("Voyage-3-Large", "voyage"),
        ("TII/Falcon-180B", "tii"),
        # OpenAI o-series 只在独立 token 边界上识别。
        ("openrouter/o1-preview", "openai"),
        ("O3-mini", "openai"),
        ("vendor/modelo1preview", None),
        ("radio3active", None),
        # 相似拼写和未知本地模型必须保留芯片图标。
        ("groq/llama-guard", "llama"),
        ("groq/custom-model", None),
        ("ollama/unknown", None),
        ("acme/experimental", None),
        ("", None),
        ("   ", None),
        (None, None),
    ]
    script = f"""
global.window = global;
require({json.dumps(str(MODEL_FAMILY_JAVASCRIPT))});
const assert = require("assert");
const api = global.NumojModelFamily;
assert.ok(api, "NumojModelFamily was not exported");
for (const [model, expected] of {json.dumps(cases)}) {{
  assert.strictEqual(
    api.detect(model),
    expected,
    `detect(${{JSON.stringify(model)}})`
  );
  const expectedClass = expected
    ? `model-family-logo model-family-logo--${{expected}}`
    : "fas fa-microchip";
  assert.strictEqual(
    api.iconClass(model),
    expectedClass,
    `iconClass(${{JSON.stringify(model)}})`
  );
}}
"""

    subprocess.run(
        [NODE, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )


def test_every_supported_family_has_one_parseable_svg_asset():
    """CSS 声明、家族集合与实际可解析的 SVG 资产必须一一对应。"""

    stylesheet = MODEL_FAMILY_STYLESHEET.read_text(encoding="utf-8")
    declarations = re.findall(
        r"\.model-family-logo--([a-z0-9-]+)\s*\{[^{}]*"
        r"background-image:\s*url\([\"']?model-family-logos/"
        r"([a-z0-9-]+\.svg)[\"']?\)[^{}]*\}",
        stylesheet,
        flags=re.DOTALL,
    )
    mapping = dict(declarations)

    assert len(declarations) == len(mapping), "同一家族不应重复声明 CSS 图标"
    assert set(mapping) == MODEL_FAMILIES
    assert len(mapping) == 29

    declared_assets = set()
    for family, filename in mapping.items():
        assert filename == f"{family}.svg"
        asset = MODEL_FAMILY_ASSET_DIRECTORY / filename
        assert asset.is_file(), f"缺少 {family} 的 SVG 资产"
        assert asset.stat().st_size > 0

        root = ElementTree.parse(asset).getroot()
        assert root.tag.rsplit("}", 1)[-1] == "svg"
        assert root.get("viewBox"), f"{filename} 缺少可缩放的 viewBox"
        assert any(
            element.tag.rsplit("}", 1)[-1]
            in {"circle", "ellipse", "line", "path", "polygon", "polyline", "rect"}
            for element in root.iter()
        ), f"{filename} 不包含可见矢量图形"
        declared_assets.add(filename)

    assert declared_assets == {path.name for path in MODEL_FAMILY_ASSET_DIRECTORY.glob("*.svg")}

    glm_logo = (MODEL_FAMILY_ASSET_DIRECTORY / "glm.svg").read_text(encoding="utf-8")
    assert "<title>Z.ai</title>" in glm_logo
    assert "Zhipu" not in glm_logo


def test_global_layout_and_model_logo_macro_keep_the_fallback_contract():
    """所有站点页面都应加载共享资源，宏在识别前使用安全的芯片回退。"""

    layout = (ROOT / "backend" / "templates" / "layouts" / "base.html").read_text(
        encoding="utf-8"
    )
    stylesheet_reference = "filename='app/model-family-logos.css'"
    javascript_reference = "filename='app/model-family.js'"
    assert layout.count(stylesheet_reference) == 1
    assert layout.count(javascript_reference) == 1
    assert layout.index(stylesheet_reference) < layout.index("{% block head %}")
    assert layout.index(javascript_reference) < layout.index("{% block head %}")

    macro = (ROOT / "backend" / "templates" / "components" / "model_logo.html").read_text(
        encoding="utf-8"
    )
    assert re.search(r"macro\s+model_logo\(model_name(?:,|\))", macro)
    assert re.search(r'class="fas fa-microchip(?:\{|\")', macro)
    assert "data-model-family-logo" in macro
    assert 'data-model-name="{{ model_name or \'\' }}"' in macro


def test_choice_picker_propagates_model_names_to_options_and_trigger():
    """服务端与动态选项都应把模型名传到图标和当前选中状态。"""

    template = (ROOT / "backend" / "templates" / "components" / "choice_picker.html").read_text(
        encoding="utf-8"
    )
    assert "model_name=''" in template
    assert "selected_model_name=''" in template
    assert 'data-choice-model="{{ model_name }}"' in template
    assert 'data-model-name="{{ model_name }}"' in template
    assert 'data-model-name="{{ selected_model_name }}"' in template
    assert "model_name=endpoint.model" in template
    assert re.search(
        r"choice_picker\([^\n]+(?:\n[^\n]+){0,3}state\.model\)",
        template,
    )


def test_agent_history_avatar_keeps_its_identicon_grid_below_desktop_width():
    """历史列表不能依赖只在桌面侧栏媒体查询中生效的头像样式。"""

    stylesheet = (ROOT / "frontend" / "public" / "static" / "app" / "agents" / "task-list.css").read_text(
        encoding="utf-8"
    )
    avatar_rule = re.search(
        r"\.agent-history-avatar\s*\{(?P<body>[^{}]+)\}", stylesheet
    )
    assert avatar_rule
    body = avatar_rule.group("body")
    assert "display: grid" in body
    assert "grid-template-columns: repeat(8, 1fr)" in body
    assert ".agent-history-avatar > span.is-filled" in stylesheet

    javascript = (ROOT / "frontend" / "public" / "static" / "app" / "choice-picker.js").read_text(
        encoding="utf-8"
    )
    assert re.search(r"entry\.model\s*\|\|\s*['\"]['\"]", javascript)
    assert "NumojModelFamily.iconClass(model)" in javascript
    assert "option.setAttribute('data-choice-model', model)" in javascript
    assert "selected.getAttribute('data-choice-model')" in javascript
    assert "icon.setAttribute('data-model-name', selectedModel)" in javascript
    assert "icon.removeAttribute('data-model-name')" in javascript


def _css_block_end(source: str, opening_brace: int) -> int:
    depth = 0
    for index in range(opening_brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError("CSS 块缺少闭合大括号")


def test_file_preview_hides_header_side_only_at_the_desktop_breakpoint():
    """三栏模式只在桌面隐藏右上信息，窄屏仍保留移动端控制。"""

    stylesheet = (ROOT / "frontend" / "public" / "static" / "app" / "agents" / "conversation.css").read_text(
        encoding="utf-8"
    )
    selector_pattern = re.compile(
        r"\.agent-session\.has-file\s+\.agent-session-header-side\s*"
        r"\{(?P<body>[^{}]*)\}",
        flags=re.DOTALL,
    )
    selector_rules = list(selector_pattern.finditer(stylesheet))
    assert len(selector_rules) == 1
    target_rule = selector_rules[0]
    assert re.search(r"\bdisplay\s*:\s*none\s*;", target_rule.group("body"))

    media_pattern = re.compile(r"@media\s*\(\s*min-width\s*:\s*992px\s*\)\s*\{")
    desktop_media_blocks = []
    for match in media_pattern.finditer(stylesheet):
        opening_brace = stylesheet.find("{", match.start())
        desktop_media_blocks.append(
            (opening_brace, _css_block_end(stylesheet, opening_brace))
        )

    assert desktop_media_blocks
    assert any(
        start < target_rule.start() < target_rule.end() < end
        for start, end in desktop_media_blocks
    )
