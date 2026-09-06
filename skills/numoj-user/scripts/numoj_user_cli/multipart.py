"""有明确 Content-Length 的流式文件上传，避免 requests 整包缓冲。"""

from __future__ import annotations

import os
import uuid

from urllib3.fields import RequestField
from requests.utils import to_key_val_list


class MultipartUpload:
    """调用方持有并关闭文件；每次迭代从创建时的文件位置重读。"""

    def __init__(self, metadata, files):
        boundary = uuid.uuid4().hex
        self.content_type = f"multipart/form-data; boundary={boundary}"
        self.parts = []
        self.length = 0
        for name, values in to_key_val_list(metadata):
            for value in values if isinstance(values, (list, tuple)) else [values]:
                if value is None:
                    continue
                field = RequestField(name=name, data=None)
                field.make_multipart()
                self._bytes(f"--{boundary}\r\n{field.render_headers()}".encode())
                payload = value if isinstance(value, bytes) else str(value).encode()
                self._bytes(payload + b"\r\n")
        for name, (filename, handle) in to_key_val_list(files):
            field = RequestField(name=name, data=None, filename=filename)
            field.make_multipart()
            self._bytes(f"--{boundary}\r\n{field.render_headers()}".encode())
            start = handle.tell()
            size = os.fstat(handle.fileno()).st_size - start
            self.parts.append((handle, start, size))
            self.length += size
            self._bytes(b"\r\n")
        self._bytes(f"--{boundary}--\r\n".encode())

    def _bytes(self, value):
        self.parts.append(value)
        self.length += len(value)

    def __len__(self):
        return self.length

    def __iter__(self):
        for part in self.parts:
            if isinstance(part, bytes):
                yield part
                continue
            handle, start, remaining = part
            handle.seek(start)
            while remaining:
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise OSError("文件在上传过程中被截断")
                remaining -= len(chunk)
                yield chunk
