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

from flask import Flask, Response, request, send_from_directory
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


def send_precompressed_directory(
    directory: str | Path,
    filename: str,
    *,
    max_age: int | None = None,
    immutable: bool = False,
):
    """从任意构建目录发送预压缩文件，适用于 Vite 内容指纹资源。"""

    source_path = safe_join(str(directory), filename)
    if source_path is None:
        return send_from_directory(directory, filename, max_age=max_age)
    source = Path(source_path)
    try:
        source_stat = source.stat()
    except OSError:
        return send_from_directory(directory, filename, max_age=max_age)

    qualities = _parse_accept_encoding(request.headers.get("Accept-Encoding"))
    candidates = []
    for preference, (encoding, suffix) in enumerate(
        reversed(_PRECOMPRESSED_ENCODINGS),
        start=1,
    ):
        quality = _encoding_quality(qualities, encoding)
        if quality <= 0:
            continue
        compressed_path = safe_join(str(directory), f"{filename}{suffix}")
        if compressed_path is None:
            continue
        compressed = Path(compressed_path)
        try:
            compressed_stat = compressed.stat()
        except OSError:
            continue
        if (
            compressed.is_file()
            and compressed_stat.st_mtime_ns >= source_stat.st_mtime_ns
        ):
            candidates.append((quality, preference, encoding, suffix))

    identity_quality = _encoding_quality(qualities, "identity")
    if identity_quality > 0:
        candidates.append((identity_quality, 0, "identity", ""))
    if not candidates:
        response = Response(status=406)
        response.vary.add("Accept-Encoding")
        return response

    _quality, _preference, encoding, suffix = max(candidates)
    response = send_from_directory(
        directory,
        f"{filename}{suffix}",
        conditional=True,
        etag=True,
        max_age=max_age,
        mimetype=mimetypes.guess_type(filename)[0] or "application/octet-stream",
        download_name=filename,
    )
    if encoding != "identity":
        response.headers["Content-Encoding"] = encoding
    response.vary.add("Accept-Encoding")
    if immutable:
        response.cache_control.public = True
        response.cache_control.immutable = True
    return response


class PrecompressedStaticFlask(Flask):
    """优先发送构建期 Brotli/Gzip 旁路文件的 Flask 应用。"""

    def __init__(self, *args, legacy_static_folder=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.legacy_static_folder = (
            str(legacy_static_folder) if legacy_static_folder else None
        )

    def _send_identity_static_file(self, filename, *, directory=None):
        response = (
            send_from_directory(directory, filename)
            if directory is not None
            else super().send_static_file(filename)
        )
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

        source_path = safe_join(static_folder, filename)
        source = Path(source_path) if source_path is not None else None
        if source is None or not source.is_file():
            legacy_folder = self.legacy_static_folder
            legacy_path = (
                safe_join(legacy_folder, filename) if legacy_folder else None
            )
            legacy_source = Path(legacy_path) if legacy_path is not None else None
            if legacy_source is None or not legacy_source.is_file():
                return self._send_identity_static_file(filename)
            static_folder = legacy_folder
            source = legacy_source

        qualities = _parse_accept_encoding(request.headers.get("Accept-Encoding"))
        try:
            source_stat = source.stat()
        except OSError:
            return self._send_identity_static_file(
                filename,
                directory=(
                    static_folder
                    if static_folder != self.static_folder
                    else None
                ),
            )

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
        return self._send_identity_static_file(
            filename,
            directory=(
                static_folder if static_folder != self.static_folder else None
            ),
        )


__all__ = ["PrecompressedStaticFlask", "send_precompressed_directory"]
