# -*- coding: utf-8 -*-
"""单元测试：db_services 中的三个归一化纯函数。

被测（参考 §1b + 源码 db_services.py:300/364/370/381）：
- normalize_written_grading_model(value, default=_DEFAULT_WRITTEN_GRADING_MODEL)
- normalize_programming_grading_model(value, default=_DEFAULT_PROGRAMMING_GRADING_MODEL)
- normalize_programming_output_filename(value, default='output.png')

源码确认的行为：
- 两个 *_grading_model：str(value or "").strip().lower()；命中各自 _ALLOWED_* 集合则保留，
  否则回退到 default（再 strip().lower()）。
- output_filename：strip → 反斜杠转正斜杠 → 含 "/" 时取最后一段并 strip → 空则用 default →
  超过 255 截断 → 最终 `text or "output.png"`。**不强制小写**。

为不被具体 config 取值绑死，模型相关断言直接引用 db_services 的模块级常量
(_ALLOWED_* / _DEFAULT_*)，这些常量由 config 的 QWEN_TEXT_MODEL / AI_TUTOR_MODEL /
QWEN_OMNI_MODEL 派生。
"""
from oj_modules import db_services as db


# --------------------------------------------------------------------------
# normalize_written_grading_model
# --------------------------------------------------------------------------

def test_written_model_keeps_allowed_value():
    """allowed 集合里的值（小写化后）应原样保留。"""
    assert db._ALLOWED_WRITTEN_GRADING_MODELS, "allowed written 集合不应为空"
    allowed = next(iter(db._ALLOWED_WRITTEN_GRADING_MODELS))
    assert db.normalize_written_grading_model(allowed) == allowed


def test_written_model_lowercases_before_match():
    """大写输入小写化后若落在 allowed 集合内则保留为小写形式。"""
    assert db._ALLOWED_WRITTEN_GRADING_MODELS
    allowed = next(iter(db._ALLOWED_WRITTEN_GRADING_MODELS))
    upper = allowed.upper()
    assert db.normalize_written_grading_model(upper) == allowed


def test_written_model_invalid_falls_back_to_default():
    """非法值 → 默认值（_DEFAULT_WRITTEN_GRADING_MODEL，小写）。"""
    expected = str(db._DEFAULT_WRITTEN_GRADING_MODEL or "").strip().lower()
    assert db.normalize_written_grading_model("totally-not-a-model-xyz") == expected


def test_written_model_empty_and_none_fall_back_to_default():
    """空串 / None → 默认值。"""
    expected = str(db._DEFAULT_WRITTEN_GRADING_MODEL or "").strip().lower()
    assert db.normalize_written_grading_model("") == expected
    assert db.normalize_written_grading_model(None) == expected
    assert db.normalize_written_grading_model("   ") == expected


def test_written_model_custom_default_used_on_invalid():
    """传入的 default 在非法时被采用（且会被 strip().lower()）。"""
    assert db.normalize_written_grading_model("nope", default="  Custom-Fallback  ") == "custom-fallback"


# --------------------------------------------------------------------------
# normalize_programming_grading_model
# --------------------------------------------------------------------------

def test_programming_model_keeps_allowed_value():
    assert db._ALLOWED_PROGRAMMING_GRADING_MODELS, "allowed programming 集合不应为空"
    allowed = next(iter(db._ALLOWED_PROGRAMMING_GRADING_MODELS))
    assert db.normalize_programming_grading_model(allowed) == allowed


def test_programming_model_lowercases_before_match():
    assert db._ALLOWED_PROGRAMMING_GRADING_MODELS
    allowed = next(iter(db._ALLOWED_PROGRAMMING_GRADING_MODELS))
    assert db.normalize_programming_grading_model(allowed.upper()) == allowed


def test_programming_model_invalid_falls_back_to_default():
    expected = str(db._DEFAULT_PROGRAMMING_GRADING_MODEL or "").strip().lower()
    assert db.normalize_programming_grading_model("garbage-model-123") == expected


def test_programming_model_empty_and_none_fall_back_to_default():
    expected = str(db._DEFAULT_PROGRAMMING_GRADING_MODEL or "").strip().lower()
    assert db.normalize_programming_grading_model("") == expected
    assert db.normalize_programming_grading_model(None) == expected


# --------------------------------------------------------------------------
# normalize_programming_output_filename
# --------------------------------------------------------------------------

def test_output_filename_keeps_plain_legal_name():
    """普通合法文件名原样保留（不强制小写）。"""
    assert db.normalize_programming_output_filename("result.png") == "result.png"
    assert db.normalize_programming_output_filename("Result.PNG") == "Result.PNG"


def test_output_filename_empty_defaults_to_output_png():
    """空 / None / 纯空白 → 'output.png'。"""
    assert db.normalize_programming_output_filename("") == "output.png"
    assert db.normalize_programming_output_filename(None) == "output.png"
    assert db.normalize_programming_output_filename("   ") == "output.png"


def test_output_filename_takes_last_path_component_backslash():
    """Windows 风格反斜杠路径 → 取最后一段，结果不含分隔符。"""
    out = db.normalize_programming_output_filename("dir\\sub\\img.png")
    assert out == "img.png"
    assert "\\" not in out and "/" not in out


def test_output_filename_takes_last_path_component_forwardslash():
    """正斜杠路径 → 取最后一段。"""
    out = db.normalize_programming_output_filename("a/b/c/photo.jpg")
    assert out == "photo.jpg"
    assert "/" not in out


def test_output_filename_preserves_case_of_last_component():
    """确认源码行为：取最后一段后不做小写化。"""
    out = db.normalize_programming_output_filename("dir\\sub\\img.PNG")
    assert out == "img.PNG"


def test_output_filename_trailing_separator_yields_default():
    """以分隔符结尾（最后一段为空）→ 回退默认 'output.png'。"""
    assert db.normalize_programming_output_filename("dir/sub/") == "output.png"
    assert db.normalize_programming_output_filename("dir\\sub\\") == "output.png"


def test_output_filename_truncated_to_255():
    """超长文件名截断到 255 字符。"""
    long_name = "x" * 300 + ".png"
    out = db.normalize_programming_output_filename(long_name)
    assert len(out) == 255
    assert out == ("x" * 300 + ".png")[:255]


def test_output_filename_custom_default_on_empty():
    """空输入时使用传入的 default（会被 strip）。"""
    assert db.normalize_programming_output_filename("", default="custom.png") == "custom.png"
    assert db.normalize_programming_output_filename("  ", default="  fallback.bmp  ") == "fallback.bmp"
