#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Flask 静态资源的预压缩分发。

大型前端依赖在构建阶段生成 ``.br`` / ``.gz`` 旁路文件；请求阶段只选择已经
存在且不早于原文件的表示，避免在 Web gthread 中现场压缩数 MB JavaScript。
"""

from __future__ import annotations

import mimetypes
from pathlib import Path

from flask import Flask, request, send_from_directory
from werkzeug.utils import safe_join


_PRECOMPRESSED_ENCODINGS = (
    ("br", ".br"),
    ("gzip", ".gz"),
)


class PrecompressedStaticFlask(Flask):
    """优先发送构建期 Brotli/Gzip 旁路文件的 Flask 应用。"""

    def _send_identity_static_file(self, filename):
        response = super().send_static_file(filename)
        # 同一 URL 可能还有 br/gzip 表示。identity 也必须携带 Vary，否则共享缓存
        # 先命中未压缩响应后，会错误地把它复用给支持预压缩的客户端。
        response.vary.add("Accept-Encoding")
        return response

    def send_static_file(self, filename):
        static_folder = self.static_folder
        if not static_folder or request.method not in {"GET", "HEAD"}:
            return self._send_identity_static_file(filename)

        accepted = request.accept_encodings
        source_path = safe_join(static_folder, filename)
        if source_path is None:
            return self._send_identity_static_file(filename)
        source = Path(source_path)
        try:
            source_stat = source.stat()
        except OSError:
            return self._send_identity_static_file(filename)
        if not source.is_file():
            return self._send_identity_static_file(filename)

        mimetype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        candidates = sorted(
            _PRECOMPRESSED_ENCODINGS,
            key=lambda item: accepted[item[0]],
            reverse=True,
        )
        for encoding, suffix in candidates:
            if accepted[encoding] <= 0:
                continue
            compressed_path = safe_join(static_folder, f"{filename}{suffix}")
            if compressed_path is None:
                continue
            compressed = Path(compressed_path)
            try:
                compressed_stat = compressed.stat()
            except OSError:
                continue
            if (
                not compressed.is_file()
                or compressed_stat.st_mtime_ns < source_stat.st_mtime_ns
            ):
                continue
            response = send_from_directory(
                static_folder,
                f"{filename}{suffix}",
                conditional=True,
                etag=True,
                mimetype=mimetype,
                download_name=filename,
            )
            response.headers["Content-Encoding"] = encoding
            response.vary.add("Accept-Encoding")
            return response
        return self._send_identity_static_file(filename)


__all__ = ["PrecompressedStaticFlask"]
