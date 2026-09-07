"""当前构建请求的有界进度回调；不持久化、不跨用户共享日志。"""
from __future__ import annotations

import codecs
from contextlib import contextmanager
from contextvars import ContextVar
import re

from backend.oj_modules.observability.events import redact_text

_sink = ContextVar("vibehub_build_progress", default=None)
_ansi = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


@contextmanager
def capture(callback):
    token = _sink.set(callback)
    try:
        yield
    finally:
        _sink.reset(token)


def emit(phase, message):
    callback = _sink.get()
    if callback is not None:
        callback({"event": "progress", "phase": phase, "message": message})


class BuildOutput:
    """逐行解码 UTF-8；超长单行及累计日志均有上限，仍持续 drain 子进程。"""
    def __init__(self):
        self.callback = _sink.get()
        self.decoders = {}
        self.pending = {}
        self.total = 0
        self.truncated = False
        self.export_reported = False

    def feed(self, channel, chunk):
        if self.callback is None:
            return
        decoder = self.decoders.setdefault(channel, codecs.getincrementaldecoder("utf-8")("replace"))
        text = self.pending.get(channel, "") + decoder.decode(chunk, final=not chunk)
        lines = text.replace("\r", "\n").split("\n")
        self.pending[channel] = lines.pop()
        for line in lines:
            self.line(line)
        if not chunk or len(self.pending[channel]) > 8192:
            self.line(self.pending[channel])
            self.pending[channel] = ""

    def line(self, value):
        if not value.strip() or self.callback is None:
            return
        if self.total >= 2 * 1024 * 1024:
            if not self.truncated:
                self.callback({"event": "log", "message": "日志已达到显示上限；构建继续，最终结果仍会返回。"})
                self.truncated = True
            return
        value = _ansi.sub("", value)
        value = "".join(character for character in value if ord(character) >= 32 and ord(character) != 127)
        message = redact_text(value, max_chars=4096)
        if not self.export_reported and re.search(r"exporting (?:to|layers)|sending tarball", message):
            self.callback({"event": "progress", "phase": "export", "message": "正在导出并加载完整镜像；此阶段仍需等待。"})
            self.export_reported = True
        self.total += len(message.encode("utf-8"))
        self.callback({"event": "log", "message": message})
