"""ELO 对战详情 text/html 输出协议的纯函数契约。"""

import json

from backend.oj_modules.ranking.match_details import normalize_match_detail_output


def test_explicit_text_output_accepts_stored_json_string():
    stored = json.dumps({
        "format": "text",
        "content": "A 的策略更稳定",
    }, ensure_ascii=False)

    assert normalize_match_detail_output(stored) == {
        "format": "text",
        "content": "A 的策略更稳定",
    }


def test_explicit_html_output_preserves_dynamic_markup_and_height():
    html = "<div id='arena'></div><script>startBattle()</script>"

    assert normalize_match_detail_output({
        "format": "HTML",
        "content": html,
        "height": "640",
    }) == {
        "format": "html",
        "content": html,
        "height": 640,
    }


def test_html_height_uses_default_and_is_clamped():
    assert normalize_match_detail_output({
        "format": "html",
        "content": "<p>default</p>",
    })["height"] == 520
    assert normalize_match_detail_output({
        "format": "html",
        "content": "<p>small</p>",
        "height": 10,
    })["height"] == 240
    assert normalize_match_detail_output({
        "format": "html",
        "content": "<p>large</p>",
        "height": 5000,
    })["height"] == 1200


def test_legacy_string_and_preferred_object_field_remain_text():
    assert normalize_match_detail_output("A wins") == {
        "format": "text",
        "content": "A wins",
    }
    assert normalize_match_detail_output({
        "winner": 1,
        "reason": "旧对象理由",
        "diagnostics": [1, 2],
    }) == {
        "format": "text",
        "content": "旧对象理由",
    }


def test_legacy_arbitrary_object_is_pretty_printed_as_text():
    output = normalize_match_detail_output({"scores": [3, 2]})

    assert output["format"] == "text"
    assert json.loads(output["content"]) == {"scores": [3, 2]}
    assert "\n" in output["content"]


def test_format_without_content_does_not_change_legacy_behavior():
    output = normalize_match_detail_output({"format": "html", "reason": "仍是文本"})

    assert output == {"format": "text", "content": "仍是文本"}


def test_script_error_and_empty_details_have_text_fallbacks():
    assert normalize_match_detail_output(
        {"format": "html", "content": "<script>run()</script>"},
        error_message="boom",
    ) == {
        "format": "text",
        "content": "【脚本错误】\nboom",
    }
    assert normalize_match_detail_output(None) == {
        "format": "text",
        "content": "（评测脚本未输出 details 字段）",
    }
