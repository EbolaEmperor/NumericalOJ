#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Flask 静态资源的预压缩分发。

大型前端依赖在构建阶段生成 ``.br`` / ``.gz`` 旁路文件；请求阶段只选择已经
存在且不早于原文件的表示，避免在 Web gthread 中现场压缩数 MB JavaScript。
"""

from __future__ import annotations

import mimetypes
from pathlib import Path
import re

from flask import Flask, request, send_from_directory
from werkzeug.utils import safe_join


_PRECOMPRESSED_ENCODINGS = (
    ("br", ".br"),
    ("gzip", ".gz"),
)
_QUALITY_VALUE_RE = re.compile(
    r"(?:0(?:\.\d{0,3})?|1(?:\.0{0,3})?|\.\d{1,3})\Z"
)


def _parse_accept_encoding(value: str | None) -> dict[str, float]:
    """解析静态资源需要的 Accept-Encoding 子集。

    Werkzeug 严格按 RFC qvalue 语法解析，会把常见但缺少前导零的 ``q=.8``
    整项丢弃。这里兼容该写法；其他畸形 q 项直接忽略，不把它误当成显式 q=0。
    """
    qualities: dict[str, float] = {}
    for item in (value or "").split(","):
        parts = [part.strip() for part in item.split(";")]
        encoding = parts[0].lower()
        if not encoding:
            continue
        quality: float | None = 1.0
        for parameter in parts[1:]:
            name, separator, raw_value = parameter.partition("=")
            if separator and name.strip().lower() == "q":
                raw_value = raw_value.strip()
                quality = (
                    float(raw_value)
                    if _QUALITY_VALUE_RE.fullmatch(raw_value)
                    else None
                )
                break
        if quality is None:
            continue
        qualities[encoding] = max(qualities.get(encoding, 0.0), quality)
    return qualities


def _encoding_quality(
    qualities: dict[str, float],
    encoding: str,
) -> float:
    if encoding in qualities:
        return qualities[encoding]
    wildcard = qualities.get("*")
    if encoding == "identity":
        # identity 默认可接受；只有显式 identity;q=0，或没有更具体 identity
        # 时的 *;q=0，才能排除未编码表示。
        return 0.0 if wildcard == 0.0 else 1.0
    return wildcard if wildcard is not None else 0.0


class PrecompressedStaticFlask(Flask):
    """优先发送构建期 Brotli/Gzip 旁路文件的 Flask 应用。"""

    def _send_identity_static_file(self, filename):
        response = super().send_static_file(filename)
        # 同一 URL 可能还有 br/gzip 表示。identity 也必须携带 Vary，否则共享缓存
        # 先命中未压缩响应后，会错误地把它复用给支持预压缩的客户端。
        response.vary.add("Accept-Encoding")
        return response

    def _not_acceptable_static_response(self):
        response = self.response_class(status=406)
        response.vary.add("Accept-Encoding")
        return response

    def send_static_file(self, filename):
        static_folder = self.static_folder
        if not static_folder or request.method not in {"GET", "HEAD"}:
            return self._send_identity_static_file(filename)

        qualities = _parse_accept_encoding(request.headers.get("Accept-Encoding"))
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
        # q 值优先；同 q 时按 br、gzip、identity 的服务端顺序选择，既保留压缩
        # 收益，也确保显式偏好 identity 的客户端不会被强制发送 gzip。
        candidates = []
        for preference, (encoding, suffix) in enumerate(
            reversed(_PRECOMPRESSED_ENCODINGS),
            start=1,
        ):
            quality = _encoding_quality(qualities, encoding)
            if quality <= 0:
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
            candidates.append((quality, preference, encoding, suffix))

        identity_quality = _encoding_quality(qualities, "identity")
        if identity_quality > 0:
            candidates.append((identity_quality, 0, "identity", ""))
        if not candidates:
            return self._not_acceptable_static_response()

        _quality, _preference, encoding, suffix = max(candidates)
        if encoding != "identity":
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
