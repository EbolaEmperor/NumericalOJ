"""按调用上下文显式启用的 LLM 传输记录；默认不记录任何内容。"""

from contextlib import contextmanager
from contextvars import ContextVar

import requests


_capture = ContextVar("llm_exchange_capture", default=None)
_purpose = ContextVar("llm_exchange_purpose", default="grading")


@contextmanager
def capture_exchanges(recorder):
    token = _capture.set(recorder)
    try:
        yield
    finally:
        _capture.reset(token)


@contextmanager
def exchange_purpose(purpose):
    token = _purpose.set(purpose)
    try:
        yield
    finally:
        _purpose.reset(token)


def begin_exchange(payload):
    recorder = _capture.get()
    return recorder.begin_exchange(payload, _purpose.get()) if recorder is not None else None


class CapturedResponse:
    """在 requests 解压后的 body 字节进入解析器前落盘，保留 SSE 包装和思考内容。"""

    def __init__(self, response, exchange):
        self._response = response
        self._exchange = exchange

    def __getattr__(self, name):
        return getattr(self._response, name)

    def iter_content(self, chunk_size=1, decode_unicode=False):
        # 此处调用者均请求 bytes；不能为记录改变字符解码或流式边界。
        try:
            for chunk in self._response.iter_content(chunk_size=chunk_size, decode_unicode=decode_unicode):
                self._exchange.write(chunk)
                yield chunk
            self._exchange.body_complete()
        except GeneratorExit:
            raise
        except BaseException as error:
            self._exchange.failed(type(error).__name__)
            raise

    def iter_lines(self, chunk_size=512, decode_unicode=False, delimiter=None):
        yield from requests.Response.iter_lines(
            self, chunk_size=chunk_size, decode_unicode=decode_unicode, delimiter=delimiter,
        )

    def json(self):
        # 使用 requests 原来的 JSON 解码规则，同时记录解析失败的原文。
        self.read_body()
        return self._response.json()

    def read_body(self):
        chunks = list(self.iter_content(chunk_size=8192, decode_unicode=False))
        self._response._content = b"".join(chunks)
        self._response._content_consumed = True

    def close(self):
        try:
            self._response.close()
        finally:
            self._exchange.close()
