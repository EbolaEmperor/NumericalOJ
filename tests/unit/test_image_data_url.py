# -*- coding: utf-8 -*-
"""单元测试：ai.transcription._build_image_data_url 的格式兼容。

重点回归：图片题输出可能是 BMP（或 GIF 等）。视觉模型对 BMP 支持不稳，
因此发送前必须就地无损转成 PNG；而 PNG/JPEG/WEBP 这类“视觉安全”格式保持原样。
导入 AI 转写模块依赖 tracked backend/oj_modules/config.py；CI 网络拓扑由环境变量注入。
"""
import base64
import io

import pytest

PIL = pytest.importorskip("PIL")
from PIL import Image  # noqa: E402

from backend.oj_modules.ai import transcription  # noqa: E402


def _decode_data_url(url):
    head, b64 = url.split(",", 1)
    return head, base64.b64decode(b64)


def test_bmp_is_transcoded_to_png(tmp_path):
    p = tmp_path / "output.bmp"
    Image.new("RGB", (8, 8), (20, 150, 200)).save(str(p))
    url = transcription._build_image_data_url(str(p))
    head, raw = _decode_data_url(url)
    assert head == "data:image/png;base64"
    # 解出来的字节确实是合法 PNG（魔数）
    assert raw[:8] == b"\x89PNG\r\n\x1a\n"
    # 内容仍可被 PIL 读回，尺寸不变
    with Image.open(io.BytesIO(raw)) as im:
        assert im.format == "PNG"
        assert im.size == (8, 8)


def test_gif_is_transcoded_to_png(tmp_path):
    p = tmp_path / "output.gif"
    Image.new("P", (6, 6)).save(str(p))
    url = transcription._build_image_data_url(str(p))
    head, raw = _decode_data_url(url)
    assert head == "data:image/png;base64"
    assert raw[:8] == b"\x89PNG\r\n\x1a\n"


def test_png_is_passed_through_unchanged(tmp_path):
    p = tmp_path / "output.png"
    Image.new("RGB", (8, 8), (1, 2, 3)).save(str(p))
    url = transcription._build_image_data_url(str(p))
    head, raw = _decode_data_url(url)
    assert head == "data:image/png;base64"
    # 透传：data-uri 解出的字节应与磁盘原文件逐字节一致
    assert raw == p.read_bytes()


def test_jpeg_keeps_jpeg_mime(tmp_path):
    p = tmp_path / "output.jpg"
    Image.new("RGB", (8, 8), (9, 9, 9)).save(str(p), format="JPEG")
    url = transcription._build_image_data_url(str(p))
    head, raw = _decode_data_url(url)
    # JPEG 属于视觉安全格式，保持原 MIME 且原样透传
    assert head == "data:image/jpeg;base64"
    assert raw == p.read_bytes()


def test_image_data_url_never_follows_proc_self_symlink(tmp_path):
    p = tmp_path / "output.png"
    p.symlink_to("/proc/self/environ")

    with pytest.raises(OSError):
        transcription._build_image_data_url(str(p))
