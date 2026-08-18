# -*- coding: utf-8 -*-
"""题目本地字段归一化的纯函数单测。

题目 AI 能力已改用 ``llm_endpoint_bindings``，不再按配置文件维护模型白名单；
本文件只覆盖仍由题目表直接保存的输出图片文件名。
"""

from oj_modules import db_services as db
import pytest


def test_legacy_model_normalizers_are_removed():
    assert not hasattr(db, "normalize_written_grading_model")
    assert not hasattr(db, "normalize_programming_grading_model")
    assert not hasattr(db, "_ALLOWED_WRITTEN_GRADING_MODELS")
    assert not hasattr(db, "_ALLOWED_PROGRAMMING_GRADING_MODELS")


def test_output_filename_keeps_plain_legal_name():
    assert db.normalize_output_image_filename("result.png") == "result.png"
    assert db.normalize_output_image_filename("Result.PNG") == "Result.PNG"


def test_output_filename_empty_defaults_to_output_png():
    assert db.normalize_output_image_filename("") == "output.png"
    assert db.normalize_output_image_filename(None) == "output.png"
    assert db.normalize_output_image_filename("   ") == "output.png"


def test_output_filename_takes_last_path_component():
    assert db.normalize_output_image_filename("dir\\sub\\img.png") == "img.png"
    assert db.normalize_output_image_filename("a/b/c/photo.jpg") == "photo.jpg"


def test_output_filename_preserves_case_of_last_component():
    assert db.normalize_output_image_filename("dir\\sub\\img.PNG") == "img.PNG"


def test_output_filename_trailing_separator_yields_default():
    assert db.normalize_output_image_filename("dir/sub/") == "output.png"
    assert db.normalize_output_image_filename("dir\\sub\\") == "output.png"


def test_output_filename_truncated_to_255():
    long_name = "x" * 300 + ".png"
    out = db.normalize_output_image_filename(long_name)
    assert len(out) == 255
    assert out.endswith(".png")
    assert out == "x" * 251 + ".png"


def test_output_filename_custom_default_on_empty():
    assert db.normalize_output_image_filename("", default="custom.png") == "custom.png"
    assert (
        db.normalize_output_image_filename("  ", default="  fallback.bmp  ")
        == "fallback.bmp"
    )


@pytest.mark.parametrize(
    "filename",
    ["output.txt", "result.csv", "image.svg", "no-extension", "output\x00.png"],
)
def test_output_filename_rejects_unsupported_image_extensions(filename):
    with pytest.raises(ValueError, match="输出图片文件名"):
        db.normalize_output_image_filename(filename)
