"""VibeHub 不可信作品的离线镜像构建、按需容器和 UDS HTTP 代理。

作品容器没有网络命名空间中的可用接口，也不发布端口。应用只允许在容器内有界
``/run/vibehub`` tmpfs 中创建 ``app.sock``，宿主通过受信任的 ``docker exec`` relay
转发经过净化和限额的 HTTP 请求。容器根层可写但随实例销毁；平台只把按数据库
project id 与通道隔离的受管 Docker volume 挂到 ``/data``，作品不能选择宿主路径。

运行状态位于权限为 0700 的宿主目录，并用 ``flock`` 只串行化短暂的 state
预留与 CAS 提交。Docker start/stop、健康探测等不可信 I/O 全部在锁外执行，避免一个
慢作品阻塞其它 Gunicorn worker 的 heartbeat/release。原始 lease token 只返回给
调用方；磁盘仅保存 SHA-256 摘要。
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import base64
import fcntl
import hashlib
import hmac
import json
import logging
import math
import os
from pathlib import Path
import re
import secrets
import selectors
import shlex
import signal
import stat
import struct
import subprocess
import threading
import time
from typing import Callable, Iterable, Mapping, Sequence
import unicodedata
from urllib.parse import quote, urljoin, urlsplit

from oj_modules.project_paths import PROJECT_ROOT
from oj_modules.vibehub import storage


MANAGED_IMAGE_LABEL = "com.numericaloj.vibehub.image"
MANAGED_CONTAINER_LABEL = "com.numericaloj.vibehub.managed"
MANAGER_SCOPE_LABEL = "com.numericaloj.vibehub.scope"
RUNTIME_ID_LABEL = "com.numericaloj.vibehub.runtime-id"
SOURCE_DIGEST_LABEL = "com.numericaloj.vibehub.source-sha256"
MANAGED_DATA_VOLUME_LABEL = "com.numericaloj.vibehub.data-volume"
DATA_STORAGE_KEY_LABEL = "com.numericaloj.vibehub.storage-key"

DEFAULT_BASE_IMAGE = "numericaloj-vibehub-runtime:1"
DEFAULT_RUNTIME_ROOT = PROJECT_ROOT / "tmp" / "vibehub_runtime"
DEFAULT_BASE_OCI_LAYOUT_ROOT = PROJECT_ROOT / ".deploy" / "vibehub-base-oci"
APP_SOCKET_PATH = storage.SOCKET_PATH
HEALTH_PATH = storage.HEALTH_PATH

GIB = 1024 ** 3
STANDARD_IMAGE_BYTES = 20 * GIB
FEATURED_IMAGE_BYTES = 40 * GIB
STANDARD_MEMORY = "4g"
FEATURED_MEMORY = "8g"
STANDARD_CPUS = "2"
FEATURED_CPUS = "4"
STANDARD_PIDS = 256
FEATURED_PIDS = 512
STANDARD_WRITABLE_BYTES = 4 * GIB
FEATURED_WRITABLE_BYTES = 8 * GIB

DEFAULT_LEASE_TTL_SECONDS = 90.0
DEFAULT_REQUEST_TIMEOUT_SECONDS = 15.0
DEFAULT_REQUEST_MAX_BYTES = 16 * 1024 * 1024
DEFAULT_RESPONSE_MAX_BYTES = 16 * 1024 * 1024
DEFAULT_BUILD_TIMEOUT_SECONDS = 480.0
MAX_BUILD_TIMEOUT_SECONDS = 540.0
DEFAULT_BUILD_SLOT_TIMEOUT_SECONDS = 5.0
DEFAULT_PROXY_SLOT_TIMEOUT_SECONDS = 0.25
DEFAULT_HEALTH_PROBE_SLOT_TIMEOUT_SECONDS = 0.1
DEFAULT_MAX_ACTIVE_RUNTIMES = 8
MAX_ACTIVE_RUNTIMES = 64
START_RESERVATION_TTL_SECONDS = 45.0
STOP_RESERVATION_TTL_SECONDS = 45.0
DEFAULT_BUILD_CACHE_MAX_BYTES = 4 * GIB
MIN_BUILD_CACHE_MAX_BYTES = 256 * 1024 * 1024
MAX_BUILD_CACHE_MAX_BYTES = 100 * GIB
BUILD_CONCURRENCY = 1
PROXY_CONCURRENCY = 8
HEALTH_PROBE_CONCURRENCY = 4
_COMMAND_OUTPUT_LIMIT = 128 * 1024
_MAX_STATE_BYTES = 4 * 1024 * 1024
_MAX_DOCKERFILE_BYTES = 256 * 1024
_MAX_OCI_METADATA_BYTES = 1024 * 1024
_MAX_DOCKERFILE_INSTRUCTIONS = 64
_MAX_DOCKERFILE_COPIES = 16
_MAX_CONTEXT_ENTRIES = 20_000
_MAX_CONTEXT_BYTES = 2 * GIB
SOCKET_TMPFS_BYTES = 16 * 1024 * 1024
_RELAY_MAGIC = b"VHR1"
_RELAY_METADATA_MAX_BYTES = 64 * 1024
_PROXY_BODY_HARD_MAX_BYTES = 64 * 1024 * 1024
_PROCESS_BUILD_SEMAPHORE = threading.BoundedSemaphore(BUILD_CONCURRENCY)
_PROCESS_PROXY_SEMAPHORE = threading.BoundedSemaphore(PROXY_CONCURRENCY)
_PROCESS_HEALTH_PROBE_SEMAPHORE = threading.BoundedSemaphore(
    HEALTH_PROBE_CONCURRENCY
)


def _validated_build_timeout_seconds(value) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("VIBEHUB_BUILD_TIMEOUT_SECONDS 必须是有限数字") from exc
    if not math.isfinite(timeout) or not 1 <= timeout <= MAX_BUILD_TIMEOUT_SECONDS:
        raise ValueError(
            "VIBEHUB_BUILD_TIMEOUT_SECONDS 必须在 1–540 秒之间"
        )
    return timeout


def _validated_max_active_runtimes(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("VIBEHUB_MAX_ACTIVE_RUNTIMES 必须是整数")
    if not 1 <= value <= MAX_ACTIVE_RUNTIMES:
        raise ValueError("VIBEHUB_MAX_ACTIVE_RUNTIMES 必须在 1–64 之间")
    return value


def _validated_build_cache_max_bytes(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("VIBEHUB_BUILD_CACHE_MAX_BYTES 必须是整数")
    if not MIN_BUILD_CACHE_MAX_BYTES <= value <= MAX_BUILD_CACHE_MAX_BYTES:
        raise ValueError("VIBEHUB_BUILD_CACHE_MAX_BYTES 必须在 256 MiB–100 GiB 之间")
    return value


_IMAGE_REFERENCE_RE = re.compile(
    r"^(?:[a-zA-Z0-9][a-zA-Z0-9._-]*(?::[0-9]+)?/)*"
    r"[a-zA-Z0-9][a-zA-Z0-9._-]*"
    r"(?::[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127})?"
    r"(?:@sha256:[0-9a-f]{64})?$"
)
_PROJECT_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_CHANNEL_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_RUNTIME_ID_RE = re.compile(r"^[0-9a-f]{40}$")
_STORAGE_KEY_RE = re.compile(
    r"^project-(?P<project_id>[1-9][0-9]{0,18})-(?P<channel>public|latest|review)$"
)
_DATA_VOLUME_RE = re.compile(
    r"^numoj-vh-data-[0-9a-f]{16}-project-[1-9][0-9]{0,18}-(?:public|latest|review)$"
)
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_DOCKER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

_REQUEST_HEADER_ALLOWLIST = frozenset({
    "accept",
    "accept-encoding",
    "accept-language",
    "content-type",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
    "range",
    "user-agent",
})
_RESPONSE_HEADER_ALLOWLIST = frozenset({
    "accept-ranges",
    "content-disposition",
    "content-encoding",
    "content-language",
    "content-range",
    "content-type",
    "etag",
    "last-modified",
    "location",
    "retry-after",
})
_HOP_BY_HOP_HEADERS = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
})
_DROP_RESPONSE_HEADERS = frozenset({
    "cache-control",
    "set-cookie",
    "set-cookie2",
    "content-security-policy",
    "content-security-policy-report-only",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "permissions-policy",
    "referrer-policy",
    "x-frame-options",
})
RUNTIME_CORS_METHODS = (
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE",
)
RUNTIME_CORS_REQUEST_HEADERS = ("Content-Type", "Range")
_ALLOWED_METHODS = frozenset((*RUNTIME_CORS_METHODS, "OPTIONS"))

_PROXY_CSP = (
    "sandbox allow-scripts allow-forms allow-modals allow-downloads; "
    "default-src 'self' data: blob:; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; media-src 'self' data: blob:; "
    "font-src 'self' data:; connect-src 'self'; worker-src 'self' blob:; "
    "frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; "
    "navigate-to 'self'"
)

_logger = logging.getLogger(__name__)


class VibeHubRuntimeError(RuntimeError):
    """VibeHub 构建、容器或代理安全契约无法满足。"""


class VibeHubPackageError(VibeHubRuntimeError):
    """作品构建上下文或 Dockerfile 不符合离线构建契约。"""


class VibeHubImageError(VibeHubRuntimeError):
    """镜像不存在、来源不可信或超过资源预算。"""


class VibeHubLeaseError(VibeHubRuntimeError):
    """短期运行租约不存在、过期或与请求对象不匹配。"""


class VibeHubProxyError(VibeHubRuntimeError):
    """容器 HTTP 响应无效、超时或超过代理上限。"""


class VibeHubRequestTooLarge(VibeHubProxyError):
    """代理请求体超过配置硬上限；HTTP 适配层应返回 413。"""


class VibeHubCapacityError(VibeHubRuntimeError):
    """宿主容器、构建或代理容量已满，调用方应返回 429 并稍后重试。"""


@dataclass(frozen=True)
class RuntimeLimits:
    image_bytes: int
    memory: str
    cpus: str
    pids: int
    tmpfs_bytes: int
    writable_bytes: int


@dataclass(frozen=True)
class ImageInfo:
    reference: str
    image_id: str
    size_bytes: int
    labels: Mapping[str, str]
    volumes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ImageBuildResult:
    image_ref: str
    image_id: str
    size_bytes: int
    source_digest: str
    featured: bool


@dataclass(frozen=True)
class RuntimeLease:
    token: str
    project_key: str
    channel: str
    proxy_base_path: str
    expires_at: float
    container_name: str
    socket_path: Path


@dataclass(frozen=True)
class ProxyResponse:
    status: int
    reason: str
    headers: tuple[tuple[str, str], ...]
    body: bytes


@dataclass(frozen=True)
class _CommandResult:
    returncode: int
    stdout: str
    stderr: str
    stdout_truncated: bool = False
    stderr_truncated: bool = False


@dataclass(frozen=True)
class _BinaryCommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool = False
    stderr_truncated: bool = False


class _BoundedBytes:
    def __init__(self, limit: int):
        self.limit = max(0, int(limit))
        self.value = bytearray()
        self.truncated = False

    def append(self, chunk: bytes) -> None:
        remaining = self.limit - len(self.value)
        if remaining > 0:
            self.value.extend(chunk[:remaining])
        if len(chunk) > max(0, remaining):
            self.truncated = True


def _run_binary_command(
    command: Sequence[str],
    *,
    timeout: float,
    env: Mapping[str, str] | None = None,
    input_bytes: bytes = b"",
    stdout_limit: int = _COMMAND_OUTPUT_LIMIT,
    stderr_limit: int = _COMMAND_OUTPUT_LIMIT,
) -> _BinaryCommandResult:
    """有界双向执行，超限后继续 drain，避免 relay/build 输出撑爆 Web 进程。"""

    proc = subprocess.Popen(
        [str(item) for item in command],
        stdin=subprocess.PIPE if input_bytes else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(env) if env is not None else None,
        start_new_session=True,
    )
    stdout = _BoundedBytes(stdout_limit)
    stderr = _BoundedBytes(stderr_limit)
    selector = selectors.DefaultSelector()
    assert proc.stdout is not None and proc.stderr is not None
    for pipe, target in ((proc.stdout, stdout), (proc.stderr, stderr)):
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ, target)
    payload = bytes(input_bytes)
    input_offset = 0
    if payload:
        assert proc.stdin is not None
        os.set_blocking(proc.stdin.fileno(), False)
        selector.register(proc.stdin, selectors.EVENT_WRITE, None)
    deadline = time.monotonic() + max(0.1, float(timeout))
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    proc.kill()
                raise subprocess.TimeoutExpired(list(command), timeout)
            for key, _mask in selector.select(min(0.1, remaining)):
                pipe = key.fileobj
                if key.events & selectors.EVENT_WRITE:
                    try:
                        written = os.write(
                            pipe.fileno(), payload[input_offset : input_offset + 65536]
                        )
                        input_offset += written
                    except BlockingIOError:
                        continue
                    except (BrokenPipeError, OSError):
                        input_offset = len(payload)
                    if input_offset >= len(payload):
                        try:
                            selector.unregister(pipe)
                        except Exception:
                            pass
                        pipe.close()
                    continue
                try:
                    chunk = os.read(pipe.fileno(), 65536)
                except BlockingIOError:
                    continue
                except OSError:
                    chunk = b""
                if chunk:
                    key.data.append(chunk)
                else:
                    try:
                        selector.unregister(pipe)
                    except Exception:
                        pass
                    pipe.close()
        proc.wait(timeout=max(0.1, deadline - time.monotonic()))
    finally:
        selector.close()
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            if pipe is not None and not pipe.closed:
                pipe.close()
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                proc.kill()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
    return _BinaryCommandResult(
        returncode=int(proc.returncode),
        stdout=bytes(stdout.value),
        stderr=bytes(stderr.value),
        stdout_truncated=stdout.truncated,
        stderr_truncated=stderr.truncated,
    )


def _run_command(
    command: Sequence[str],
    *,
    timeout: float,
    env: Mapping[str, str] | None = None,
    output_limit: int = _COMMAND_OUTPUT_LIMIT,
) -> _CommandResult:
    result = _run_binary_command(
        command,
        timeout=timeout,
        env=env,
        stdout_limit=output_limit,
        stderr_limit=output_limit,
    )
    return _CommandResult(
        returncode=result.returncode,
        stdout=result.stdout.decode("utf-8", errors="replace"),
        stderr=result.stderr.decode("utf-8", errors="replace"),
        stdout_truncated=result.stdout_truncated,
        stderr_truncated=result.stderr_truncated,
    )


@contextmanager
def _process_slot(semaphore, timeout: float, label: str):
    try:
        acquired = semaphore.acquire(timeout=max(0.0, float(timeout)))
    except (OverflowError, ValueError) as exc:
        raise VibeHubCapacityError(f"VibeHub {label}并发等待参数无效") from exc
    if not acquired:
        raise VibeHubCapacityError(f"VibeHub {label}并发已满，请稍后重试")
    try:
        yield
    finally:
        semaphore.release()


def limits_for(featured: bool) -> RuntimeLimits:
    if featured:
        return RuntimeLimits(
            image_bytes=FEATURED_IMAGE_BYTES,
            memory=FEATURED_MEMORY,
            cpus=FEATURED_CPUS,
            pids=FEATURED_PIDS,
            tmpfs_bytes=512 * 1024 * 1024,
            writable_bytes=FEATURED_WRITABLE_BYTES,
        )
    return RuntimeLimits(
        image_bytes=STANDARD_IMAGE_BYTES,
        memory=STANDARD_MEMORY,
        cpus=STANDARD_CPUS,
        pids=STANDARD_PIDS,
        tmpfs_bytes=256 * 1024 * 1024,
        writable_bytes=STANDARD_WRITABLE_BYTES,
    )


def _validate_image_reference(value: str) -> str:
    reference = str(value or "").strip()
    if not reference or reference.startswith("-") or not _IMAGE_REFERENCE_RE.fullmatch(reference):
        raise VibeHubImageError("VibeHub 镜像引用无效")
    return reference


def _validate_project_key(value: str) -> str:
    key = str(value or "").strip()
    if not _PROJECT_KEY_RE.fullmatch(key) or ".." in key.split("/"):
        raise VibeHubLeaseError("VibeHub project_key 无效")
    return key


def _validate_channel(value: str) -> str:
    channel = str(value or "").strip().lower()
    if not _CHANNEL_RE.fullmatch(channel):
        raise VibeHubLeaseError("VibeHub channel 无效")
    return channel


def _validate_storage_key(value: str, *, channel: str) -> str:
    key = str(value or "").strip().lower()
    match = _STORAGE_KEY_RE.fullmatch(key)
    if not match or match.group("channel") != channel:
        raise VibeHubLeaseError(
            "VibeHub storage_key 必须由真实 project id 与当前通道组成"
        )
    return key


def _validate_proxy_root(value: str) -> str:
    root = str(value or "").strip()
    parsed = urlsplit(root)
    if (
        not root.startswith("/")
        or root.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or "\\" in root
        or any(ord(char) < 0x20 for char in root)
    ):
        raise VibeHubLeaseError("VibeHub proxy base_path 必须是站内绝对路径")
    return root.rstrip("/") or "/"


def _manifest_and_dockerfile(package_dir: Path) -> tuple[dict, str]:
    try:
        root_info = package_dir.lstat()
    except OSError as exc:
        raise VibeHubPackageError("VibeHub 构建上下文不存在") from exc
    if not stat.S_ISDIR(root_info.st_mode) or package_dir.is_symlink():
        raise VibeHubPackageError("VibeHub 构建上下文必须是真实目录")

    for name, maximum in (
        (storage.MANIFEST_FILENAME, 64 * 1024),
        (storage.DOCKERFILE_NAME, _MAX_DOCKERFILE_BYTES),
    ):
        path = package_dir / name
        try:
            info = path.lstat()
        except OSError as exc:
            raise VibeHubPackageError(f"作品包缺少 {name}") from exc
        if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_size > maximum:
            raise VibeHubPackageError(f"{name} 必须是受限大小的普通文件")
    try:
        manifest = storage.validate_manifest(package_dir)
        dockerfile = (package_dir / storage.DOCKERFILE_NAME).read_text(encoding="utf-8")
    except storage.PackageValidationError as exc:
        raise VibeHubPackageError(str(exc)) from exc
    except (OSError, UnicodeError) as exc:
        raise VibeHubPackageError("Dockerfile 必须是有效 UTF-8 文本") from exc
    if "\x00" in dockerfile:
        raise VibeHubPackageError("Dockerfile 不能包含 NUL")
    return manifest, dockerfile


def _logical_dockerfile_lines(text: str) -> list[str]:
    lines = text.splitlines()
    logical: list[str] = []
    current = ""
    for raw in lines:
        stripped = raw.lstrip()
        if not current and stripped.startswith("#"):
            if re.match(r"#\s*(?:syntax|escape|check)\s*=", stripped, re.I):
                raise VibeHubPackageError("Dockerfile 不允许外部 frontend 或 parser directive")
            continue
        piece = raw.rstrip()
        continued = piece.endswith("\\") and not piece.endswith("\\\\")
        if continued:
            current += piece[:-1] + " "
            continue
        current += piece
        if current.strip():
            logical.append(current.strip())
        current = ""
    if current:
        raise VibeHubPackageError("Dockerfile 末尾存在未闭合续行")
    return logical


def _dockerfile_base_images(text: str, allowed_base_images: Iterable[str]) -> tuple[str, ...]:
    allowed = {_validate_image_reference(item) for item in allowed_base_images}
    if not allowed:
        raise VibeHubPackageError("未配置任何离线 VibeHub 基础镜像")
    logical_lines = _logical_dockerfile_lines(text)
    if len(logical_lines) > _MAX_DOCKERFILE_INSTRUCTIONS:
        raise VibeHubPackageError("Dockerfile 指令数量超限")
    allowed_instructions = frozenset({
        "FROM", "COPY", "CMD", "ENTRYPOINT", "WORKDIR", "ENV", "LABEL",
    })
    external_bases: list[str] = []
    copy_count = 0
    launch_count = 0
    from_count = 0
    for index, line in enumerate(logical_lines):
        match = re.match(r"^([A-Za-z]+)(?:\s+)(.*)$", line, re.S)
        if not match:
            raise VibeHubPackageError("Dockerfile 指令格式无效")
        instruction = match.group(1).upper()
        body = match.group(2).strip()
        if not body:
            raise VibeHubPackageError("Dockerfile 指令内容不能为空")
        if instruction not in allowed_instructions:
            raise VibeHubPackageError(
                "VibeHub MVP Dockerfile 仅允许 FROM、COPY、CMD、ENTRYPOINT、"
                "WORKDIR、ENV 和 LABEL"
            )
        if instruction == "FROM":
            from_count += 1
            if index != 0 or from_count != 1:
                raise VibeHubPackageError("VibeHub Dockerfile 只允许一个且位于首行的 FROM")
            if body.startswith("--") or "$" in body:
                raise VibeHubPackageError("FROM 必须直接引用固定的本地基础镜像")
            parts = body.split()
            if len(parts) != 1:
                raise VibeHubPackageError("VibeHub Dockerfile 禁止多阶段构建和 stage 别名")
            source = parts[0]
            if source not in allowed:
                raise VibeHubPackageError(f"基础镜像不在离线白名单：{source}")
            external_bases.append(source)
        if instruction == "COPY":
            copy_count += 1
            if copy_count > _MAX_DOCKERFILE_COPIES:
                raise VibeHubPackageError("Dockerfile COPY 指令数量超限")
            if re.search(r"(?:^|\s)--from(?:=|\s)", body, re.I):
                raise VibeHubPackageError("VibeHub Dockerfile 禁止 COPY --from")
            copy_body = body
            if body.startswith("--"):
                prefix = "--chown=65532:65532 "
                if not body.startswith(prefix) or body[len(prefix):].startswith("-"):
                    raise VibeHubPackageError(
                        "COPY 只允许精确 --chown=65532:65532 flag"
                    )
                copy_body = body[len(prefix):].lstrip()
            try:
                if copy_body.startswith("["):
                    copy_parts = json.loads(copy_body)
                    if (
                        not isinstance(copy_parts, list)
                        or len(copy_parts) < 2
                        or not all(isinstance(item, str) for item in copy_parts)
                    ):
                        raise ValueError("invalid JSON COPY")
                else:
                    copy_parts = shlex.split(copy_body, posix=True)
            except (ValueError, json.JSONDecodeError) as exc:
                raise VibeHubPackageError("Dockerfile COPY 格式无效") from exc
            if len(copy_parts) < 2:
                raise VibeHubPackageError("Dockerfile COPY 缺少源路径或目标路径")
            destination = copy_parts[-1].rstrip("/") or "/"
            if (
                destination != "/app"
                and not destination.startswith("/app/")
            ) or "$" in destination or "\\" in destination or any(
                part == ".." for part in destination.split("/")
            ):
                raise VibeHubPackageError("COPY 目标只能位于 /app，不能覆盖受信 runtime")
            for source in copy_parts[:-1]:
                if (
                    source.startswith("/")
                    or source.startswith("-")
                    or "$" in source
                    or "\\" in source
                    or any(part == ".." for part in source.split("/"))
                ):
                    raise VibeHubPackageError("COPY 源路径必须直接来自作品上下文")
        if instruction in {"CMD", "ENTRYPOINT"}:
            launch_count += 1
        if instruction == "WORKDIR":
            if (
                not body.startswith("/")
                or "\\" in body
                or "$" in body
                or any(part == ".." for part in body.split("/"))
            ):
                raise VibeHubPackageError("WORKDIR 必须是固定的容器绝对路径")
    if from_count != 1:
        raise VibeHubPackageError("Dockerfile 缺少 FROM")
    if copy_count < 1:
        raise VibeHubPackageError("Dockerfile 至少需要一个 COPY 来打包 vendored 依赖")
    if launch_count < 1:
        raise VibeHubPackageError("Dockerfile 必须通过 CMD 或 ENTRYPOINT 声明启动命令")
    return tuple(external_bases)


def _scan_context(package_dir: Path) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    total_bytes = 0
    entries = 0
    resolved_root = package_dir.resolve(strict=True)
    for current_root, dirnames, filenames in os.walk(resolved_root, topdown=True, followlinks=False):
        dirnames.sort()
        filenames.sort()
        current = Path(current_root)
        for name in [*dirnames, *filenames]:
            path = current / name
            relative = path.relative_to(resolved_root).as_posix()
            info = path.lstat()
            entries += 1
            if entries > _MAX_CONTEXT_ENTRIES:
                raise VibeHubPackageError("VibeHub 构建上下文文件数量超限")
            if stat.S_ISLNK(info.st_mode):
                raise VibeHubPackageError(f"VibeHub 构建上下文禁止符号链接：{relative}")
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise VibeHubPackageError(f"VibeHub 构建上下文禁止特殊文件：{relative}")
            digest.update(relative.encode("utf-8"))
            digest.update(b"\0d\0" if stat.S_ISDIR(info.st_mode) else b"\0f\0")
            if stat.S_ISREG(info.st_mode):
                total_bytes += int(info.st_size)
                if total_bytes > _MAX_CONTEXT_BYTES:
                    raise VibeHubPackageError("VibeHub 构建上下文总大小超限")
                with path.open("rb") as source:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
    return digest.hexdigest(), entries, total_bytes


def _effective_source_digest(
    context_digest: str,
    bases: Sequence[tuple[str, str]],
) -> str:
    """把可变 base tag 解析到不可变 image ID，组成构建缓存完整性键。"""

    if not re.fullmatch(r"[0-9a-f]{64}", context_digest):
        raise VibeHubPackageError("VibeHub 作品上下文摘要无效")
    digest = hashlib.sha256(b"numoj-vibehub-build-v2\0")
    digest.update(context_digest.encode("ascii"))
    for reference, image_id in bases:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise VibeHubImageError("VibeHub 基础镜像缺少不可变 image ID")
        digest.update(b"\0")
        digest.update(reference.encode("utf-8"))
        digest.update(b"\0")
        digest.update(image_id.encode("ascii"))
    return digest.hexdigest()


def _inspect_build_bases(
    docker,
    bases: Sequence[str],
) -> tuple[tuple[str, str], ...]:
    resolved: list[tuple[str, str]] = []
    for reference in bases:
        image = docker.inspect_image(reference)
        if image.volumes:
            raise VibeHubImageError("VibeHub 基础镜像不得声明持久化 VOLUME")
        resolved.append((reference, image.image_id))
    return tuple(resolved)


def _encode_relay_request(
    method: str,
    target: str,
    headers: Mapping[str, str],
    body: bytes,
    *,
    timeout: float,
    response_max_bytes: int,
) -> bytes:
    if (
        method not in _ALLOWED_METHODS
        or not isinstance(target, str)
        or not isinstance(body, bytes)
        or type(response_max_bytes) is not int
        or not 1 <= response_max_bytes <= _PROXY_BODY_HARD_MAX_BYTES
        or len(body) > _PROXY_BODY_HARD_MAX_BYTES
        or type(timeout) not in {int, float}
        or isinstance(timeout, bool)
        or not math.isfinite(float(timeout))
        or not 0.1 <= float(timeout) <= 120
    ):
        raise VibeHubProxyError("VibeHub relay 请求参数无效")
    metadata = json.dumps({
        "version": 1,
        "method": method,
        "target": target,
        "headers": list(headers.items()),
        "body_length": len(body),
        "timeout_seconds": float(timeout),
        "response_max_bytes": int(response_max_bytes),
    }, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if len(metadata) > _RELAY_METADATA_MAX_BYTES:
        raise VibeHubProxyError("VibeHub relay 请求元数据过大")
    return _RELAY_MAGIC + struct.pack(">I", len(metadata)) + metadata + body


def _parse_relay_response(payload: bytes, *, response_max_bytes: int) -> ProxyResponse:
    if (
        type(response_max_bytes) is not int
        or not 1 <= response_max_bytes <= _PROXY_BODY_HARD_MAX_BYTES
    ):
        raise VibeHubProxyError("VibeHub relay 响应上限无效")
    value = bytes(payload)
    if len(value) < 8 or value[:4] != _RELAY_MAGIC:
        raise VibeHubProxyError("VibeHub relay 返回无效协议魔数")
    metadata_length = struct.unpack(">I", value[4:8])[0]
    if not 1 <= metadata_length <= _RELAY_METADATA_MAX_BYTES:
        raise VibeHubProxyError("VibeHub relay 元数据长度无效")
    metadata_end = 8 + metadata_length
    if metadata_end > len(value):
        raise VibeHubProxyError("VibeHub relay 协议帧不完整")
    try:
        metadata = json.loads(value[8:metadata_end].decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise VibeHubProxyError("VibeHub relay 元数据无法解析") from exc
    if not isinstance(metadata, dict) or set(metadata) != {
        "version", "status", "reason", "headers", "body_length",
    } or metadata.get("version") != 1:
        raise VibeHubProxyError("VibeHub relay 元数据 schema 无效")
    status = metadata["status"]
    body_length = metadata["body_length"]
    if type(status) is not int or type(body_length) is not int:
        raise VibeHubProxyError("VibeHub relay 状态字段无效")
    reason = metadata["reason"]
    raw_headers = metadata["headers"]
    if not 200 <= status <= 599 or not isinstance(reason, str) or len(reason) > 256:
        raise VibeHubProxyError("VibeHub relay HTTP 状态无效")
    if any(ord(char) < 0x20 or ord(char) == 0x7f for char in reason):
        raise VibeHubProxyError("VibeHub relay reason 包含控制字符")
    if (
        not isinstance(raw_headers, list)
        or len(raw_headers) > 100
        or any(not isinstance(item, list) or len(item) != 2 for item in raw_headers)
    ):
        raise VibeHubProxyError("VibeHub relay 响应头无效")
    headers: list[tuple[str, str]] = []
    for raw_name, raw_value in raw_headers:
        if not isinstance(raw_name, str) or not isinstance(raw_value, str):
            raise VibeHubProxyError("VibeHub relay 响应头类型无效")
        if (
            not _HEADER_NAME_RE.fullmatch(raw_name)
            or any(ord(char) < 0x20 or ord(char) == 0x7f for char in raw_value)
            or len(raw_value.encode("utf-8")) > 8192
        ):
            raise VibeHubProxyError("VibeHub relay 响应头格式无效")
        headers.append((raw_name, raw_value))
    body = value[metadata_end:]
    if (
        body_length < 0
        or body_length != len(body)
        or body_length > int(response_max_bytes)
    ):
        raise VibeHubProxyError("VibeHub relay 响应体长度无效")
    return ProxyResponse(status, reason, tuple(headers), body)


class DockerCLI:
    """只暴露 VibeHub 所需的固定 Docker CLI 操作。"""

    def __init__(
        self,
        *,
        command_runner=_run_command,
        binary_command_runner=_run_binary_command,
        build_builder: str = "",
        build_cache_max_bytes: int = DEFAULT_BUILD_CACHE_MAX_BYTES,
        base_oci_layout_root: Path | str = DEFAULT_BASE_OCI_LAYOUT_ROOT,
    ):
        self._command_runner = command_runner
        self._binary_command_runner = binary_command_runner
        self.build_builder = str(build_builder or "").strip()
        if self.build_builder and not _DOCKER_NAME_RE.fullmatch(self.build_builder):
            raise ValueError("VIBEHUB_BUILD_BUILDER 名称无效")
        self.build_cache_max_bytes = _validated_build_cache_max_bytes(
            build_cache_max_bytes
        )
        self.base_oci_layout_root = Path(base_oci_layout_root).resolve(
            strict=False
        )

    def _run(self, command: Sequence[str], *, timeout: float, env=None) -> _CommandResult:
        try:
            return self._command_runner(command, timeout=timeout, env=env)
        except FileNotFoundError as exc:
            raise VibeHubRuntimeError("Docker CLI 不存在") from exc
        except subprocess.TimeoutExpired as exc:
            raise VibeHubRuntimeError("Docker 操作超时") from exc

    def inspect_image(self, reference: str) -> ImageInfo:
        reference = _validate_image_reference(reference)
        result = self._run(
            ["docker", "image", "inspect", "--format", "{{json .}}", reference],
            timeout=20,
        )
        if result.returncode != 0:
            raise VibeHubImageError(f"VibeHub 镜像不存在或无法 inspect：{reference}")
        try:
            payload = json.loads(result.stdout.strip())
            image_id = str(payload["Id"])
            size_bytes = int(payload["Size"])
            image_config = payload.get("Config") or {}
            if not isinstance(image_config, dict):
                raise TypeError("Config must be an object")
            labels = image_config.get("Labels") or {}
            raw_volumes = image_config.get("Volumes")
            if raw_volumes is None:
                volumes = ()
            elif isinstance(raw_volumes, dict) and all(
                isinstance(path, str) and path.startswith("/")
                for path in raw_volumes
            ):
                volumes = tuple(sorted(raw_volumes))
            else:
                raise TypeError("Volumes must be null or an absolute-path object")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise VibeHubImageError("Docker image inspect 返回无效数据") from exc
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) or size_bytes < 0:
            raise VibeHubImageError("Docker image inspect 缺少可信镜像 ID 或大小")
        if not isinstance(labels, dict) or any(not isinstance(k, str) for k in labels):
            raise VibeHubImageError("Docker image labels 无效")
        return ImageInfo(reference, image_id, size_bytes, dict(labels), volumes)

    def verify_dedicated_builder(self) -> None:
        if not self.build_builder:
            return
        result = self._run(
            ["docker", "buildx", "ls", "--format", "json"],
            timeout=20,
        )
        if result.returncode != 0:
            detail = " ".join(result.stderr.split())[:300]
            suffix = f"：{detail}" if detail else ""
            raise VibeHubImageError(
                f"VibeHub 专属 Docker builder 清单读取失败"
                f"（退出码：{result.returncode}）{suffix}"
            )
        if result.stdout_truncated:
            raise VibeHubImageError("VibeHub builder 清单输出被截断")
        try:
            builders = [
                json.loads(line)
                for line in result.stdout.splitlines()
                if line.strip()
            ]
            if any(not isinstance(item, dict) for item in builders):
                raise TypeError("builder list item must be an object")
            matches = [
                item for item in builders
                if item.get("Name") == self.build_builder
            ]
            if not matches:
                raise VibeHubImageError(
                    f"VibeHub 专属 Docker builder 未预置：{self.build_builder}"
                )
            if len(matches) != 1:
                raise TypeError("duplicate builder names")
            builder = matches[0]
            builder_name = builder["Name"]
            driver = builder["Driver"]
            raw_nodes = builder["Nodes"]
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise VibeHubImageError("VibeHub builder inspect 数据无效") from exc
        if not isinstance(raw_nodes, list):
            raise VibeHubImageError("VibeHub builder nodes 数据无效")
        nodes: list[tuple[str, str]] = []
        for raw_node in raw_nodes:
            if not isinstance(raw_node, dict):
                raise VibeHubImageError("VibeHub builder node 数据无效")
            nodes.append((
                str(raw_node.get("Name") or ""),
                str(raw_node.get("Status") or "").lower(),
            ))
        node_names = [name for name, _status in nodes]
        if (
            builder_name != self.build_builder
            or driver != "docker-container"
            or not 1 <= len(nodes) <= 16
            or len(set(node_names)) != len(node_names)
            or any(
                not _DOCKER_NAME_RE.fullmatch(name) or status != "running"
                for name, status in nodes
            )
        ):
            raise VibeHubImageError(
                "VibeHub builder 必须是同名、running 且缓存隔离的 docker-container driver"
            )
        for node_name, _status in nodes:
            container_name = f"buildx_buildkit_{node_name}"
            inspected = self._run([
                "docker", "container", "inspect",
                "--format", "{{json .}}",
                container_name,
            ], timeout=20)
            if inspected.returncode != 0:
                raise VibeHubImageError("VibeHub builder node 容器不存在")
            try:
                payload = json.loads(inspected.stdout.strip())
                actual_name = str(payload["Name"]).removeprefix("/")
                running = payload["State"]["Running"]
                network_mode = payload["HostConfig"]["NetworkMode"]
            except (KeyError, TypeError, json.JSONDecodeError) as exc:
                raise VibeHubImageError(
                    "VibeHub builder node inspect 数据无效"
                ) from exc
            if (
                actual_name != container_name
                or running is not True
                or network_mode != "none"
            ):
                raise VibeHubImageError(
                    "VibeHub builder node 必须运行且 HostConfig.NetworkMode=none"
                )

    @staticmethod
    def _require_secure_owned_path(
        path: Path,
        *,
        directory: bool,
        label: str,
        maximum_bytes: int | None = None,
    ) -> os.stat_result:
        try:
            info = path.lstat()
        except OSError as exc:
            raise VibeHubImageError(f"VibeHub OCI {label} 不存在") from exc
        expected_type = stat.S_ISDIR if directory else stat.S_ISREG
        if (
            not expected_type(info.st_mode)
            or path.is_symlink()
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o022
            or (maximum_bytes is not None and info.st_size > maximum_bytes)
        ):
            raise VibeHubImageError(
                f"VibeHub OCI {label} 类型、属主、权限或大小无效"
            )
        return info

    def _base_oci_build_contexts(
        self,
        resolved_bases: Sequence[tuple[str, str]],
    ) -> tuple[str, ...]:
        """把 daemon base ID 绑定到 deploy 原子发布的本地 OCI layout。"""

        root = self.base_oci_layout_root
        self._require_secure_owned_path(root, directory=True, label="layout root")
        releases = root / "releases"
        self._require_secure_owned_path(
            releases, directory=True, label="releases directory"
        )
        current = root / "current"
        try:
            current_info = current.lstat()
            release = current.resolve(strict=True)
        except OSError as exc:
            raise VibeHubImageError("VibeHub OCI current 发布指针无效") from exc
        if (
            not stat.S_ISLNK(current_info.st_mode)
            or current_info.st_uid != os.geteuid()
        ):
            raise VibeHubImageError(
                "VibeHub OCI current 必须是部署用户拥有的原子 symlink"
            )
        if release.parent != releases.resolve(strict=True):
            raise VibeHubImageError("VibeHub OCI current 越出 releases 目录")
        self._require_secure_owned_path(
            release, directory=True, label="current release"
        )
        metadata_path = release / "metadata.json"
        self._require_secure_owned_path(
            metadata_path,
            directory=False,
            label="metadata",
            maximum_bytes=_MAX_OCI_METADATA_BYTES,
        )
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise VibeHubImageError("VibeHub OCI metadata 无法解析") from exc
        if not isinstance(metadata, dict) or metadata.get("schema_version") != 1:
            raise VibeHubImageError("VibeHub OCI metadata schema 无效")
        if len(resolved_bases) != 1:
            raise VibeHubImageError("VibeHub dedicated build 只允许一个基础镜像")
        reference, image_id = resolved_bases[0]
        image_hex = image_id.removeprefix("sha256:")
        manifest_digest = str(metadata.get("manifest_digest") or "")
        if (
            release.name != image_hex
            or metadata.get("engine_image_ref") != reference
            or metadata.get("engine_image_id") != image_id
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", manifest_digest)
        ):
            raise VibeHubImageError(
                "VibeHub OCI current 与已核验 daemon 基础镜像不一致"
            )
        for name in ("oci-layout", "index.json"):
            self._require_secure_owned_path(
                release / name,
                directory=False,
                label=name,
                maximum_bytes=_MAX_OCI_METADATA_BYTES,
            )
        raw_blobs = metadata.get("blobs")
        if not isinstance(raw_blobs, list) or not raw_blobs:
            raise VibeHubImageError("VibeHub OCI metadata blobs 无效")
        blob_sizes: dict[str, int] = {}
        for blob in raw_blobs:
            if not isinstance(blob, dict):
                raise VibeHubImageError("VibeHub OCI metadata blob 无效")
            digest = str(blob.get("digest") or "")
            size = blob.get("size")
            if (
                not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
                or isinstance(size, bool)
                or not isinstance(size, int)
                or size < 0
            ):
                raise VibeHubImageError("VibeHub OCI metadata blob 无效")
            blob_sizes[digest] = size
        if manifest_digest not in blob_sizes:
            raise VibeHubImageError("VibeHub OCI manifest 未列入 blobs")
        manifest_blob = (
            release / "blobs" / "sha256" / manifest_digest.removeprefix("sha256:")
        )
        manifest_info = self._require_secure_owned_path(
            manifest_blob,
            directory=False,
            label="manifest blob",
            maximum_bytes=_MAX_OCI_METADATA_BYTES,
        )
        if manifest_info.st_size != blob_sizes[manifest_digest]:
            raise VibeHubImageError("VibeHub OCI manifest blob 大小不一致")
        actual_manifest_digest = "sha256:" + hashlib.sha256(
            manifest_blob.read_bytes()
        ).hexdigest()
        if actual_manifest_digest != manifest_digest:
            raise VibeHubImageError("VibeHub OCI manifest blob 摘要不一致")
        try:
            index = json.loads(
                (release / "index.json").read_text(encoding="utf-8")
            )
            manifest = json.loads(manifest_blob.read_text(encoding="utf-8"))
            config_descriptor = manifest["config"]
            layer_descriptors = manifest["layers"]
        except (
            OSError,
            KeyError,
            TypeError,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            raise VibeHubImageError("VibeHub OCI manifest schema 无效") from exc
        index_manifests = index.get("manifests") if isinstance(index, dict) else None
        if not isinstance(index_manifests, list) or not any(
            isinstance(descriptor, dict)
            and descriptor.get("digest") == manifest_digest
            for descriptor in index_manifests
        ):
            raise VibeHubImageError("VibeHub OCI index 未绑定 manifest")
        if (
            not isinstance(config_descriptor, dict)
            or config_descriptor.get("digest") != image_id
            or not isinstance(layer_descriptors, list)
        ):
            raise VibeHubImageError(
                "VibeHub OCI manifest 未绑定 daemon image config ID"
            )
        referenced = [config_descriptor, *layer_descriptors]
        for descriptor in referenced:
            if not isinstance(descriptor, dict):
                raise VibeHubImageError("VibeHub OCI manifest descriptor 无效")
            digest = str(descriptor.get("digest") or "")
            size = descriptor.get("size")
            if (
                digest not in blob_sizes
                or isinstance(size, bool)
                or not isinstance(size, int)
                or blob_sizes[digest] != size
            ):
                raise VibeHubImageError(
                    "VibeHub OCI manifest descriptor 与 metadata 不一致"
                )
        uri = f"oci-layout://{release.as_posix()}@{manifest_digest}"
        return (f"{reference}={uri}",)

    def prune_managed_dangling_images(self) -> None:
        result = self._run([
            "docker", "image", "prune", "--force",
            "--filter", f"label={MANAGED_IMAGE_LABEL}=1",
        ], timeout=60)
        if result.returncode != 0:
            raise VibeHubImageError("VibeHub 受管 dangling 镜像清理失败")

    def prune_dedicated_build_cache(self) -> None:
        if not self.build_builder:
            return
        self.verify_dedicated_builder()
        result = self._run([
            "docker", "buildx", "prune",
            "--builder", self.build_builder,
            "--force",
            "--max-used-space", str(self.build_cache_max_bytes),
        ], timeout=120)
        if result.returncode != 0:
            raise VibeHubImageError("VibeHub 专属 builder 缓存清理失败")

    def remove_managed_image_reference(
        self,
        reference: str,
        expected_image_id: str,
    ) -> bool:
        """只在稳定 tag 仍指向预期受管 image ID 时移除该 tag。"""

        reference = _validate_image_reference(reference)
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(expected_image_id)):
            raise VibeHubImageError("VibeHub 待回收 image ID 无效")
        result = self._run(
            ["docker", "image", "inspect", "--format", "{{json .}}", reference],
            timeout=20,
        )
        detail = f"{result.stdout}\n{result.stderr}".strip()
        if result.returncode != 0:
            if any(marker in detail.lower() for marker in (
                "no such image",
                "no such object",
            )):
                return False
            raise VibeHubImageError("无法确认 VibeHub 镜像 tag 当前指向")
        try:
            payload = json.loads(result.stdout.strip())
            current_id = str(payload["Id"])
            image_config = payload.get("Config") or {}
            if not isinstance(image_config, dict):
                raise TypeError("Config must be object")
            labels = image_config.get("Labels") or {}
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise VibeHubImageError("Docker image inspect 返回无效数据") from exc
        if (
            current_id != expected_image_id
            or not isinstance(labels, dict)
            or labels.get(MANAGED_IMAGE_LABEL) != "1"
        ):
            return False
        result = self._run(
            ["docker", "image", "rm", reference],
            timeout=60,
        )
        detail = f"{result.stdout}\n{result.stderr}".strip()
        if result.returncode == 0:
            return True
        if any(marker in detail.lower() for marker in (
            "no such image",
            "no such object",
        )):
            return False
        raise VibeHubImageError("VibeHub 闲置镜像 tag 回收失败")

    def build(
        self,
        package_dir: Path,
        image_ref: str,
        *,
        source_digest: str,
        resolved_bases: Sequence[tuple[str, str]] = (),
        limits: RuntimeLimits,
        timeout: float,
    ) -> None:
        timeout = _validated_build_timeout_seconds(timeout)
        if self.build_builder:
            self.verify_dedicated_builder()
        if self.build_builder:
            # docker-container driver 的产物默认只留在 builder cache；必须显式
            # --load 回本机 image store。该 driver 看不到 daemon 本地镜像，FROM
            # 只能由 deploy 发布并绑定 engine config ID 的 OCI layout 覆盖。
            command = [
                "docker", "buildx", "build",
                "--builder", self.build_builder,
                "--load",
            ]
            for context in self._base_oci_build_contexts(resolved_bases):
                command.extend(["--build-context", context])
            command.extend([
                "--network", "none",
                "--pull=false",
                "--resource", f"memory={limits.memory}",
                "--resource", f"memory-swap={limits.memory}",
                "--resource", "cpu-period=100000",
                "--resource", f"cpu-quota={int(float(limits.cpus) * 100000)}",
                "--ulimit", "nofile=1024:1024",
                "--shm-size", "64m",
            ])
        else:
            command = ["docker", "build"]
            command.extend([
                "--network", "none",
                "--pull=false",
                "--force-rm",
                "--memory", limits.memory,
                "--memory-swap", limits.memory,
                "--cpu-period", "100000",
                "--cpu-quota", str(int(float(limits.cpus) * 100000)),
                "--ulimit", "nofile=1024:1024",
                "--shm-size", "64m",
            ])
        command.extend([
            "--label", f"{MANAGED_IMAGE_LABEL}=1",
            "--label", f"{SOURCE_DIGEST_LABEL}={source_digest}",
            "--tag", image_ref,
            "--file", str(package_dir / storage.DOCKERFILE_NAME),
            "--quiet",
            str(package_dir),
        ])
        environment = os.environ.copy()
        environment["DOCKER_BUILDKIT"] = "1"
        result = self._run(command, timeout=timeout, env=environment)
        initial_detail = f"{result.stdout}\n{result.stderr}".strip()
        # Docker Desktop/Colima 可能启用了 BuildKit 却没有可用 buildx 插件。仅对
        # 这个可精确识别的客户端安装问题回退 legacy builder；命令中的离线网络、
        # 资源、ulimit 和基础镜像预检保持完全相同。其它构建错误一律不降级。
        if (
            result.returncode != 0
            and not self.build_builder
            and "buildkit is enabled but the buildx component is missing or broken"
            in initial_detail.lower()
        ):
            legacy_environment = environment.copy()
            legacy_environment["DOCKER_BUILDKIT"] = "0"
            result = self._run(command, timeout=timeout, env=legacy_environment)
        detail = f"{result.stdout}\n{result.stderr}".strip()
        lowered = detail.lower()
        if result.returncode != 0:
            raise VibeHubImageError(f"VibeHub 镜像离线构建失败：{detail[:1000]}")
        if any(marker in lowered for marker in (
            "network mode \"host\" is not allowed",
            "security mode \"insecure\" is not allowed",
            "not supported by buildkit",
        )):
            raise VibeHubImageError("当前 Docker builder 无法落实 VibeHub 构建隔离参数")

    def run_container(self, args: Sequence[str]) -> None:
        result = self._run(args, timeout=45)
        if result.returncode != 0:
            detail = f"{result.stdout}\n{result.stderr}".strip()
            raise VibeHubRuntimeError(f"VibeHub 容器启动失败：{detail[:1000]}")

    def ensure_data_volume(
        self,
        name: str,
        *,
        scope: str,
        storage_key: str,
    ) -> None:
        if not _DATA_VOLUME_RE.fullmatch(name):
            raise VibeHubRuntimeError("VibeHub data volume 名称无效")
        expected = {
            MANAGED_DATA_VOLUME_LABEL: "1",
            MANAGER_SCOPE_LABEL: scope,
            DATA_STORAGE_KEY_LABEL: storage_key,
        }
        label_args: list[str] = []
        for key, value in expected.items():
            label_args.extend(["--label", f"{key}={value}"])
        # create 对同名 volume 幂等；随后仍完整核验，避免复用异物。
        created = self._run([
            "docker", "volume", "create", "--driver", "local",
            *label_args, name,
        ], timeout=15)
        if created.returncode != 0 or created.stdout.strip() != name:
            raise VibeHubRuntimeError("无法创建受管 VibeHub data volume")
        inspect = self._run([
            "docker", "volume", "inspect", "--format", "{{json .}}", name,
        ], timeout=15)
        try:
            payload = json.loads(inspect.stdout.strip())
            labels = payload.get("Labels") or {}
            options = payload.get("Options") or {}
        except (AttributeError, json.JSONDecodeError) as exc:
            raise VibeHubRuntimeError("Docker data volume inspect 返回无效数据") from exc
        if (
            inspect.returncode != 0
            or payload.get("Name") != name
            or payload.get("Driver") != "local"
            or payload.get("Scope") != "local"
            or labels != expected
            or options
        ):
            raise VibeHubRuntimeError("VibeHub data volume 身份或驱动不可信")

    def verify_data_writable(self, container_name: str) -> None:
        probe = "/data/.vibehub-write-probe"
        script = (
            "import os; p=" + repr(probe)
            + "; fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);"
            " os.close(fd); os.unlink(p)"
        )
        result = self._run([
            "docker", "exec", "--user", "65532:65532", container_name,
            "/usr/local/bin/python", "-I", "-S", "-c", script,
        ], timeout=10)
        if result.returncode != 0:
            raise VibeHubRuntimeError("受管 VibeHub /data 不可由作品用户写入")

    def remove_container(self, name: str) -> None:
        last_detail = ""
        for _attempt in range(2):
            result = self._run(["docker", "rm", "-f", name], timeout=15)
            detail = f"{result.stdout}\n{result.stderr}".strip()
            if result.returncode == 0 or "no such container" in detail.lower():
                return
            last_detail = detail or f"docker rm exited {result.returncode}"
        raise VibeHubRuntimeError(f"无法确认 VibeHub 容器已删除：{last_detail[:500]}")

    def container_running(self, name: str) -> bool:
        result = self._run(
            ["docker", "container", "inspect", "--format", "{{.State.Running}}", name],
            timeout=10,
        )
        if result.returncode != 0:
            return False
        value = result.stdout.strip().lower()
        if value not in {"true", "false"}:
            raise VibeHubRuntimeError("Docker container inspect 返回无效状态")
        return value == "true"

    def list_scoped_containers(self, scope: str) -> tuple[str, ...]:
        result = self._run([
            "docker", "container", "ls", "--all",
            "--filter", f"label={MANAGED_CONTAINER_LABEL}=1",
            "--filter", f"label={MANAGER_SCOPE_LABEL}={scope}",
            "--format", "{{.Names}}",
        ], timeout=15)
        if result.returncode != 0:
            raise VibeHubRuntimeError("无法枚举受管 VibeHub 容器")
        names = tuple(line.strip() for line in result.stdout.splitlines() if line.strip())
        if any(not re.fullmatch(r"numoj-vh-[0-9a-f-]+", name) for name in names):
            raise VibeHubRuntimeError("Docker 返回了异常的 VibeHub 容器名")
        return names

    def container_labels(self, name: str) -> Mapping[str, str] | None:
        result = self._run([
            "docker", "container", "inspect", "--format", "{{json .Config.Labels}}", name,
        ], timeout=10)
        if result.returncode != 0:
            return None
        try:
            labels = json.loads(result.stdout.strip()) or {}
        except json.JSONDecodeError as exc:
            raise VibeHubRuntimeError("Docker container labels 无法解析") from exc
        if not isinstance(labels, dict):
            raise VibeHubRuntimeError("Docker container labels 无效")
        return labels

    def relay_http(
        self,
        container_name: str,
        method: str,
        target: str,
        headers: Mapping[str, str],
        body: bytes,
        *,
        timeout: float,
        response_max_bytes: int,
    ) -> ProxyResponse:
        if not re.fullmatch(r"numoj-vh-[0-9a-f]{16}-[0-9a-f]{40}", container_name):
            raise VibeHubProxyError("VibeHub relay 容器名无效")
        if method not in _ALLOWED_METHODS:
            raise VibeHubProxyError("VibeHub relay 方法无效")
        if (
            type(timeout) not in {int, float}
            or isinstance(timeout, bool)
            or type(response_max_bytes) is not int
            or not isinstance(body, bytes)
            or not math.isfinite(float(timeout))
            or not 0.1 <= float(timeout) <= 120
            or not 1 <= response_max_bytes <= _PROXY_BODY_HARD_MAX_BYTES
            or len(body) > _PROXY_BODY_HARD_MAX_BYTES
        ):
            raise VibeHubProxyError("VibeHub relay 限额无效")
        request_frame = _encode_relay_request(
            method,
            target,
            headers,
            body,
            timeout=timeout,
            response_max_bytes=response_max_bytes,
        )
        command = [
            "docker", "exec", "-i", "--user", "65532:65532",
            container_name,
            "/usr/local/bin/vibehub-uds-relay",
        ]
        try:
            result = self._binary_command_runner(
                command,
                timeout=float(timeout) + 3.0,
                input_bytes=request_frame,
                stdout_limit=int(response_max_bytes) + _RELAY_METADATA_MAX_BYTES + 8,
                stderr_limit=16 * 1024,
            )
        except FileNotFoundError as exc:
            raise VibeHubProxyError("Docker CLI 不存在，无法执行 VibeHub relay") from exc
        except subprocess.TimeoutExpired as exc:
            raise VibeHubProxyError("VibeHub docker exec relay 超时") from exc
        if result.returncode != 0 or result.stdout_truncated or result.stderr_truncated:
            raise VibeHubProxyError("VibeHub docker exec relay 执行失败")
        return _parse_relay_response(
            result.stdout,
            response_max_bytes=response_max_bytes,
        )


def build_image(
    package_dir: Path | str,
    image_ref: str,
    *,
    featured: bool = False,
    allowed_base_images: Iterable[str] = (DEFAULT_BASE_IMAGE,),
    docker_client: DockerCLI | None = None,
    timeout_seconds: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
    slot_timeout_seconds: float = DEFAULT_BUILD_SLOT_TIMEOUT_SECONDS,
) -> ImageBuildResult:
    """在无网络且基础镜像已预置的前提下构建一个受管作品镜像。"""

    timeout_seconds = _validated_build_timeout_seconds(timeout_seconds)
    root = Path(package_dir)
    image_ref = _validate_image_reference(image_ref)
    _manifest, dockerfile = _manifest_and_dockerfile(root)
    bases = _dockerfile_base_images(dockerfile, allowed_base_images)
    context_digest, _entries, _bytes = _scan_context(root)
    docker = docker_client or DockerCLI()
    with _process_slot(
        _PROCESS_BUILD_SEMAPHORE,
        slot_timeout_seconds,
        "镜像构建",
    ):
        # Docker 在本地缺少 FROM 时即使 --pull=false 仍可能拉取；先逐个 inspect，
        # 任何缺失都在 build 之前失败关闭。
        resolved_bases = _inspect_build_bases(docker, bases)
        source_digest = _effective_source_digest(context_digest, resolved_bases)
        limits = limits_for(featured)
        docker.build(
            root,
            image_ref,
            source_digest=source_digest,
            resolved_bases=resolved_bases,
            limits=limits,
            timeout=float(timeout_seconds),
        )
        rebuilt_context_digest, _rebuilt_entries, _rebuilt_bytes = _scan_context(root)
        if rebuilt_context_digest != context_digest:
            raise VibeHubPackageError("VibeHub 构建期间作品目录发生变化")
        rebuilt_bases = _inspect_build_bases(docker, bases)
        if rebuilt_bases != resolved_bases:
            raise VibeHubImageError("VibeHub 构建期间基础镜像 tag 发生变化")
        image = docker.inspect_image(image_ref)
        if image.labels.get(MANAGED_IMAGE_LABEL) != "1":
            raise VibeHubImageError("构建结果缺少 VibeHub 受管镜像标签")
        if image.labels.get(SOURCE_DIGEST_LABEL) != source_digest:
            raise VibeHubImageError("构建结果与作品包摘要不一致")
        if image.volumes:
            raise VibeHubImageError("VibeHub 镜像不得声明持久化 VOLUME")
        if image.size_bytes > limits.image_bytes:
            raise VibeHubImageError(
                f"VibeHub 镜像超过 {'40' if featured else '20'} GiB 预算"
            )
    return ImageBuildResult(
        image_ref=image_ref,
        image_id=image.image_id,
        size_bytes=image.size_bytes,
        source_digest=source_digest,
        featured=bool(featured),
    )


def image_reference_for(project_key: str, *, channel: str = "public") -> str:
    key = _validate_project_key(project_key)
    selected_channel = _validate_channel(channel)
    # 路由传入 ``<slug>@vN``。tag 只绑定作品身份和 latest/public/review 通道，
    # SOURCE_DIGEST_LABEL 再绑定该通道当前内容；发布或编辑重建同一稳定 tag，旧
    # image layer 变为 dangling，而已经启动的容器仍安全地持有旧 image ID。
    versioned = re.fullmatch(r"(.+)@v[1-9][0-9]*", key)
    project_identity = versioned.group(1) if versioned else key
    digest_input = f"{project_identity}\0{selected_channel}".encode("utf-8")
    digest = hashlib.sha256(digest_input).hexdigest()[:32]
    return f"numoj-vibehub:{digest}"


def _quote_uri_component(value: str, *, safe: str) -> str:
    """NFC 规范化 Unicode，同时保留已有的有效百分号编码。"""

    normalized = unicodedata.normalize("NFC", value)
    output: list[str] = []
    index = 0
    while index < len(normalized):
        char = normalized[index]
        if (
            char == "%"
            and index + 2 < len(normalized)
            and re.fullmatch(r"[0-9A-Fa-f]{2}", normalized[index + 1 : index + 3])
        ):
            output.append("%" + normalized[index + 1 : index + 3].upper())
            index += 3
            continue
        output.append(quote(char, safe=safe, encoding="utf-8", errors="strict"))
        index += 1
    return "".join(output)


def _safe_request_target(value: str) -> str:
    target = unicodedata.normalize("NFC", str(value or ""))
    try:
        parsed = urlsplit(target)
    except ValueError as exc:
        raise VibeHubProxyError("VibeHub 代理路径无效") from exc
    if (
        not target.startswith("/")
        or target.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or parsed.fragment
        or "\\" in target
        or len(target.encode("utf-8")) > 8192
        or any(ord(char) < 0x20 or ord(char) == 0x7f for char in target)
    ):
        raise VibeHubProxyError("VibeHub 代理路径无效")
    normalized_path = _quote_uri_component(
        parsed.path,
        safe="/:@!$&'()*+,;=-._~",
    )
    normalized_query = _quote_uri_component(
        parsed.query,
        safe="/:@!$&'()*+,;=?-._~",
    )
    result = normalized_path or "/"
    if parsed.query or "?" in target:
        result += "?" + normalized_query
    if len(result.encode("ascii")) > 8192:
        raise VibeHubProxyError("VibeHub 代理路径过长")
    return result


def _sanitize_request_headers(
    headers: Mapping[str, str] | Sequence[tuple[str, str]],
    *,
    base_path: str,
    session_id: str,
) -> dict[str, str]:
    items = headers.items() if isinstance(headers, Mapping) else headers
    clean: dict[str, str] = {}
    count = 0
    for raw_name, raw_value in items:
        count += 1
        if count > 100:
            raise VibeHubProxyError("VibeHub 请求头数量超限")
        name = str(raw_name)
        value = str(raw_value)
        lowered = name.lower()
        if not _HEADER_NAME_RE.fullmatch(name) or "\r" in value or "\n" in value:
            raise VibeHubProxyError("VibeHub 请求头格式无效")
        if len(value.encode("utf-8")) > 8192:
            raise VibeHubProxyError("VibeHub 请求头过长")
        if lowered in _REQUEST_HEADER_ALLOWLIST:
            clean[name] = value
    clean["Host"] = "vibehub.internal"
    clean["Connection"] = "close"
    clean["X-VibeHub-Base-Path"] = base_path
    clean["X-VibeHub-Session-Id"] = session_id
    # sandbox iframe 没有 allow-same-origin，浏览器 Origin 为 null。由可信代理
    # 固定该值，不能把 OJ Origin、Cookie、Authorization 或 CSRF token 交给作品。
    clean["Origin"] = "null"
    return clean


def _sanitize_response(
    response: ProxyResponse,
    *,
    base_path: str,
    request_target: str = "/",
) -> ProxyResponse:
    if type(response.status) is not int or not 200 <= response.status <= 599:
        raise VibeHubProxyError("VibeHub 响应状态不受支持")
    if any(ord(char) < 0x20 or ord(char) == 0x7f for char in response.reason):
        raise VibeHubProxyError("VibeHub 响应 reason 包含控制字符")
    if len(response.headers) > 100:
        raise VibeHubProxyError("VibeHub 响应头数量超限")

    def rewrite_location(raw_value: str) -> str | None:
        if (
            "\\" in raw_value
            or any(ord(char) < 0x20 or ord(char) == 0x7f for char in raw_value)
        ):
            return None
        try:
            parsed_location = urlsplit(raw_value)
        except ValueError:
            return None
        if parsed_location.scheme or parsed_location.netloc or raw_value.startswith("//"):
            return None
        origin = "http://vibehub.internal"
        resolved = urlsplit(urljoin(origin + request_target, raw_value))
        if resolved.scheme != "http" or resolved.netloc != "vibehub.internal":
            return None
        internal = _safe_request_target(
            resolved.path + (("?" + resolved.query) if resolved.query else "")
        )
        base = base_path.rstrip("/")
        if internal == base or internal.startswith(base + "/") or internal.startswith(base + "?"):
            rewritten = internal
        else:
            rewritten = base + internal
        if parsed_location.fragment:
            rewritten += "#" + _quote_uri_component(
                parsed_location.fragment,
                safe="/:@!$&'()*+,;=?-._~",
            )
        return rewritten

    output: list[tuple[str, str]] = []
    for name, value in response.headers:
        lowered = name.lower()
        if lowered not in _RESPONSE_HEADER_ALLOWLIST:
            continue
        if (
            any(ord(char) < 0x20 or ord(char) == 0x7f for char in value)
            or not _HEADER_NAME_RE.fullmatch(name)
            or len(value.encode("utf-8")) > 8192
        ):
            raise VibeHubProxyError("VibeHub 响应头格式无效")
        if lowered == "location":
            rewritten = rewrite_location(value)
            if rewritten is None:
                continue
            value = rewritten
        output.append((name, value))
    output.extend([
        ("Content-Length", str(len(response.body))),
        ("Cache-Control", "no-store"),
        ("Content-Security-Policy", _PROXY_CSP),
        ("Referrer-Policy", "no-referrer"),
        ("X-Content-Type-Options", "nosniff"),
        ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
        # 只允许没有 allow-same-origin 的 sandbox iframe（Origin: null）读取自己的
        # lease URL；作品返回的任意 CORS 头已在上方剥离。
        ("Access-Control-Allow-Origin", "null"),
        ("Access-Control-Allow-Methods", ", ".join(RUNTIME_CORS_METHODS)),
        ("Access-Control-Allow-Headers", ", ".join(RUNTIME_CORS_REQUEST_HEADERS)),
    ])
    return ProxyResponse(response.status, response.reason, tuple(output), response.body)


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _empty_state() -> dict:
    return {"schema_version": 1, "runtimes": {}, "leases": {}}


class VibeHubRuntimeManager:
    """共享宿主状态的按需 VibeHub 容器管理器。"""

    def __init__(
        self,
        runtime_root: Path | str = DEFAULT_RUNTIME_ROOT,
        *,
        docker_client: DockerCLI | None = None,
        allowed_base_images: Iterable[str] = (DEFAULT_BASE_IMAGE,),
        lease_ttl_seconds: float = DEFAULT_LEASE_TTL_SECONDS,
        request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        request_max_bytes: int = DEFAULT_REQUEST_MAX_BYTES,
        response_max_bytes: int = DEFAULT_RESPONSE_MAX_BYTES,
        proxy_transport: str = "docker-exec",
        build_timeout_seconds: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
        build_slot_timeout_seconds: float = DEFAULT_BUILD_SLOT_TIMEOUT_SECONDS,
        proxy_slot_timeout_seconds: float = DEFAULT_PROXY_SLOT_TIMEOUT_SECONDS,
        health_probe_slot_timeout_seconds: float = (
            DEFAULT_HEALTH_PROBE_SLOT_TIMEOUT_SECONDS
        ),
        max_active_runtimes: int = DEFAULT_MAX_ACTIVE_RUNTIMES,
        build_builder: str = "",
        require_dedicated_builder: bool = False,
        build_cache_max_bytes: int = DEFAULT_BUILD_CACHE_MAX_BYTES,
        base_oci_layout_root: Path | str = DEFAULT_BASE_OCI_LAYOUT_ROOT,
        reaper_interval_seconds: float | None = None,
        clock=time.time,
    ):
        self.runtime_root = Path(runtime_root).resolve(strict=False)
        self.state_path = self.runtime_root / "state.json"
        self.lock_path = self.runtime_root / "state.lock"
        self.secret_path = self.runtime_root / "lease.key"
        self.build_cleanup_pending_path = (
            self.runtime_root / "build-cleanup.pending"
        )
        self.build_builder = str(build_builder or "").strip()
        if self.build_builder and not _DOCKER_NAME_RE.fullmatch(self.build_builder):
            raise ValueError("VIBEHUB_BUILD_BUILDER 名称无效")
        if type(require_dedicated_builder) is not bool:
            raise ValueError("VIBEHUB_REQUIRE_DEDICATED_BUILDER 必须是布尔值")
        self.require_dedicated_builder = require_dedicated_builder
        if self.require_dedicated_builder and not self.build_builder:
            raise ValueError(
                "要求专属 builder 时 VIBEHUB_BUILD_BUILDER 不能为空"
            )
        self.build_cache_max_bytes = _validated_build_cache_max_bytes(
            build_cache_max_bytes
        )
        raw_oci_root = Path(base_oci_layout_root)
        self.base_oci_layout_root = (
            raw_oci_root
            if raw_oci_root.is_absolute()
            else PROJECT_ROOT / raw_oci_root
        ).resolve(strict=False)
        self.docker = docker_client or DockerCLI(
            build_builder=self.build_builder,
            build_cache_max_bytes=self.build_cache_max_bytes,
            base_oci_layout_root=self.base_oci_layout_root,
        )
        self.allowed_base_images = tuple(allowed_base_images)
        self.lease_ttl_seconds = float(lease_ttl_seconds)
        self.request_timeout_seconds = float(request_timeout_seconds)
        self.request_max_bytes = int(request_max_bytes)
        self.response_max_bytes = int(response_max_bytes)
        selected_transport = str(proxy_transport or "docker-exec").strip().lower()
        if selected_transport == "auto":
            selected_transport = "docker-exec"
        if selected_transport != "docker-exec":
            raise ValueError(
                "VIBEHUB_PROXY_TRANSPORT 只允许 docker-exec；host-uds 已禁用"
            )
        self.proxy_transport = selected_transport
        self.build_timeout_seconds = _validated_build_timeout_seconds(
            build_timeout_seconds
        )
        self.build_slot_timeout_seconds = float(build_slot_timeout_seconds)
        self.proxy_slot_timeout_seconds = float(proxy_slot_timeout_seconds)
        self.health_probe_slot_timeout_seconds = float(
            health_probe_slot_timeout_seconds
        )
        self.max_active_runtimes = _validated_max_active_runtimes(
            max_active_runtimes
        )
        self.reaper_interval_seconds = float(
            reaper_interval_seconds
            if reaper_interval_seconds is not None
            else min(30.0, self.lease_ttl_seconds / 3.0)
        )
        self._clock = clock
        self._reconciled = False
        self._reconcile_once_lock = threading.Lock()
        self._thread_lock = threading.RLock()
        self._reaper_stop = threading.Event()
        self._reaper_thread: threading.Thread | None = None
        if not math.isfinite(self.lease_ttl_seconds) or not 10 <= self.lease_ttl_seconds <= 3600:
            raise ValueError("VibeHub lease TTL 必须在 10–3600 秒之间")
        if not math.isfinite(self.request_timeout_seconds) or not 0.1 <= self.request_timeout_seconds <= 120:
            raise ValueError("VibeHub proxy timeout 必须在 0.1–120 秒之间")
        if not (
            0 < self.request_max_bytes <= _PROXY_BODY_HARD_MAX_BYTES
            and 0 < self.response_max_bytes <= _PROXY_BODY_HARD_MAX_BYTES
        ):
            raise ValueError("VibeHub proxy body limits 必须在 1–64 MiB 之间")
        if (
            not math.isfinite(self.build_slot_timeout_seconds)
            or not 0 <= self.build_slot_timeout_seconds <= 120
        ):
            raise ValueError("VibeHub build slot timeout 必须在 0–120 秒之间")
        if (
            not math.isfinite(self.proxy_slot_timeout_seconds)
            or not 0 <= self.proxy_slot_timeout_seconds <= 10
        ):
            raise ValueError("VibeHub proxy slot timeout 必须在 0–10 秒之间")
        if (
            not math.isfinite(self.health_probe_slot_timeout_seconds)
            or not 0 <= self.health_probe_slot_timeout_seconds <= 5
        ):
            raise ValueError("VibeHub health probe slot timeout 必须在 0–5 秒之间")
        if (
            not math.isfinite(self.reaper_interval_seconds)
            or not 0.05 <= self.reaper_interval_seconds < self.lease_ttl_seconds
        ):
            raise ValueError("VibeHub reaper 间隔必须为 0.05 秒以上且小于 lease TTL")
        self._prepare_runtime_root()
        self._secret = self._load_or_create_secret()
        self.scope = hashlib.sha256(os.fspath(self.runtime_root).encode("utf-8")).hexdigest()[:16]

    def _build_cleanup_is_pending(self) -> bool:
        try:
            info = self.build_cleanup_pending_path.lstat()
        except FileNotFoundError:
            return False
        if (
            not stat.S_ISREG(info.st_mode)
            or self.build_cleanup_pending_path.is_symlink()
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_size > 64
        ):
            raise VibeHubRuntimeError(
                "VibeHub build cleanup marker 类型、属主或权限无效"
            )
        return True

    def _mark_build_cleanup_pending(self) -> None:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_TRUNC
            | getattr(os, "O_NOFOLLOW", 0)
        )
        fd = os.open(self.build_cleanup_pending_path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise VibeHubRuntimeError(
                    "VibeHub build cleanup marker 属主或类型无效"
                )
            os.fchmod(fd, 0o600)
            os.write(fd, b"pending\n")
            os.fsync(fd)
        finally:
            os.close(fd)

    def _clear_build_cleanup_pending(self) -> None:
        if not self._build_cleanup_is_pending():
            return
        self.build_cleanup_pending_path.unlink()

    def _cleanup_build_artifacts(self) -> None:
        """只清受管 dangling images 与专属 builder cache。"""

        self.docker.prune_managed_dangling_images()
        self.docker.prune_dedicated_build_cache()
        self._clear_build_cleanup_pending()

    def _prepare_runtime_root(self) -> None:
        self.runtime_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = self.runtime_root.lstat()
        if not stat.S_ISDIR(info.st_mode) or self.runtime_root.is_symlink():
            raise VibeHubRuntimeError("VibeHub runtime_root 必须是真实目录")
        os.chmod(self.runtime_root, 0o700)

    def _load_or_create_secret(self) -> bytes:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.secret_path, flags, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise VibeHubRuntimeError("VibeHub lease.key 属主或类型无效")
            os.fchmod(fd, 0o600)
            value = os.read(fd, 128)
            if not value:
                value = secrets.token_bytes(32)
                os.lseek(fd, 0, os.SEEK_SET)
                os.write(fd, value)
                os.ftruncate(fd, len(value))
                os.fsync(fd)
            if len(value) != 32:
                raise VibeHubRuntimeError("VibeHub lease.key 长度无效")
            return value
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _new_token(self) -> str:
        nonce = secrets.token_bytes(32)
        signature = hmac.digest(self._secret, nonce, "sha256")
        return base64.urlsafe_b64encode(nonce + signature).rstrip(b"=").decode("ascii")

    def _verify_token(self, token: str) -> str:
        value = str(token or "")
        try:
            raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except Exception as exc:
            raise VibeHubLeaseError("VibeHub lease token 无效") from exc
        if len(raw) != 64 or not hmac.compare_digest(
            raw[32:], hmac.digest(self._secret, raw[:32], "sha256")
        ):
            raise VibeHubLeaseError("VibeHub lease token 无效")
        return _token_digest(value)

    def _session_id_for_token(self, token: str) -> str:
        """生成只能由宿主重算、不会泄露 bearer token 的玩家会话标识。"""

        # 先验证签名，防止任意攻击者把此接口当作通用 HMAC oracle。
        self._verify_token(token)
        digest = hmac.digest(
            self._secret,
            b"vibehub-session\0" + token.encode("ascii"),
            "sha256",
        )
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    def _load_state(self) -> dict:
        try:
            info = self.state_path.lstat()
        except FileNotFoundError:
            return _empty_state()
        if (
            not stat.S_ISREG(info.st_mode)
            or self.state_path.is_symlink()
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_size > _MAX_STATE_BYTES
        ):
            raise VibeHubRuntimeError("VibeHub runtime state 类型、属主或大小无效")
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise VibeHubRuntimeError("VibeHub runtime state 无法解析") from exc
        if (
            not isinstance(state, dict)
            or state.get("schema_version") != 1
            or not isinstance(state.get("runtimes"), dict)
            or not isinstance(state.get("leases"), dict)
        ):
            raise VibeHubRuntimeError("VibeHub runtime state schema 无效")
        return state

    def _write_state(self, state: dict) -> None:
        payload = json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if len(payload.encode("utf-8")) > _MAX_STATE_BYTES:
            raise VibeHubRuntimeError("VibeHub runtime state 超过上限")
        temporary = self.runtime_root / f".state-{os.getpid()}-{secrets.token_hex(8)}.tmp"
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", closefd=False) as output:
                output.write(payload)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.close(fd)
            fd = -1
            os.replace(temporary, self.state_path)
            directory_fd = os.open(self.runtime_root, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    @contextmanager
    def _locked_state(self):
        with self._thread_lock:
            fd = os.open(
                self.lock_path,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                    raise VibeHubRuntimeError("VibeHub state.lock 属主或类型无效")
                os.fchmod(fd, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
                state = self._load_state()
                try:
                    yield state
                finally:
                    self._write_state(state)
            finally:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)

    @contextmanager
    def _locked_image_build(self, image_ref: str):
        """按目标 tag 串行化长时间构建，不阻塞现有 lease 的 heartbeat。"""

        lock_name = hashlib.sha256(image_ref.encode("utf-8")).hexdigest()[:32]
        path = self.runtime_root / f"build-{lock_name}.lock"
        fd = os.open(
            path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise VibeHubRuntimeError("VibeHub build lock 属主或类型无效")
            os.fchmod(fd, 0o600)
            deadline = time.monotonic() + self.build_slot_timeout_seconds
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise VibeHubCapacityError("VibeHub 同版本构建正在进行，请稍后重试")
                    time.sleep(min(0.02, max(0.001, deadline - time.monotonic())))
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    @contextmanager
    def _file_capacity_slot(self, label: str, count: int, timeout: float):
        """用共享 flock 把并发上限落实到整台宿主，而非单个 Gunicorn 进程。"""

        deadline = time.monotonic() + max(0.0, float(timeout))
        while True:
            for index in range(count):
                path = self.runtime_root / f"{label}-{index}.lock"
                fd = os.open(
                    path,
                    os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                try:
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                        raise VibeHubRuntimeError("VibeHub capacity lock 属主或类型无效")
                    os.fchmod(fd, 0o600)
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        os.close(fd)
                        continue
                    try:
                        yield
                    finally:
                        try:
                            fcntl.flock(fd, fcntl.LOCK_UN)
                        finally:
                            os.close(fd)
                    return
                except Exception:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    raise
            if time.monotonic() >= deadline:
                raise VibeHubCapacityError(f"VibeHub {label}并发已满，请稍后重试")
            time.sleep(min(0.02, max(0.001, deadline - time.monotonic())))

    @contextmanager
    def _proxy_capacity_slot(self):
        with _process_slot(
            _PROCESS_PROXY_SEMAPHORE,
            self.proxy_slot_timeout_seconds,
            "代理",
        ):
            with self._file_capacity_slot(
                "proxy-slot",
                PROXY_CONCURRENCY,
                self.proxy_slot_timeout_seconds,
            ):
                yield

    @contextmanager
    def _health_probe_capacity_slot(self):
        """独立限制健康探测，避免慢 /healthz 耗尽 Web worker。"""

        with _process_slot(
            _PROCESS_HEALTH_PROBE_SEMAPHORE,
            self.health_probe_slot_timeout_seconds,
            "健康探测",
        ):
            with self._file_capacity_slot(
                "health-probe-slot",
                HEALTH_PROBE_CONCURRENCY,
                self.health_probe_slot_timeout_seconds,
            ):
                yield

    def _runtime_id(
        self,
        project_key: str,
        channel: str,
        image_id: str,
        featured: bool,
        storage_key: str,
    ) -> str:
        payload = (
            f"{project_key}\0{channel}\0{image_id}\0{int(featured)}\0{storage_key}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:40]

    def _data_volume_name(self, storage_key: str) -> str:
        name = f"numoj-vh-data-{self.scope}-{storage_key}"
        if not _DATA_VOLUME_RE.fullmatch(name):
            raise VibeHubRuntimeError("VibeHub data volume 名称无效")
        return name

    def _container_name(self, runtime_id: str) -> str:
        if not _RUNTIME_ID_RE.fullmatch(runtime_id):
            raise VibeHubRuntimeError("VibeHub runtime_id 无效")
        return f"numoj-vh-{self.scope}-{runtime_id}"

    def _container_args(
        self,
        *,
        runtime_id: str,
        image_id: str,
        featured: bool,
        data_volume: str,
    ) -> list[str]:
        if not _DATA_VOLUME_RE.fullmatch(data_volume):
            raise VibeHubRuntimeError("VibeHub data volume 名称无效")
        limits = limits_for(featured)
        name = self._container_name(runtime_id)
        args = [
            "docker", "run", "--detach", "--rm", "--init",
            "--name", name,
            "--pull", "never",
            "--label", f"{MANAGED_CONTAINER_LABEL}=1",
            "--label", f"{MANAGER_SCOPE_LABEL}={self.scope}",
            "--label", f"{RUNTIME_ID_LABEL}={runtime_id}",
            "--network", "none",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges=true",
            "--ipc", "none",
            "--cgroupns", "private",
            "--user", "65532:65532",
            "--memory", limits.memory,
            "--memory-swap", limits.memory,
            # 直接使用 cgroup period/quota 表达 CPU 上限。``--cpus 4`` 会在
            # 只有 2 vCPU 的本地 Docker VM 上被 daemon 拒绝；quota=400000
            # 在较小宿主上自然受物理 CPU 限制，在生产 4+ 核宿主上仍精确封顶 4 核。
            "--cpu-period", "100000",
            "--cpu-quota", str(int(float(limits.cpus) * 100000)),
            "--pids-limit", str(limits.pids),
            "--storage-opt", f"size={limits.writable_bytes}",
            "--ulimit", f"nproc={limits.pids}:{limits.pids}",
            "--ulimit", "nofile=1024:1024",
            "--ulimit", "core=0:0",
            "--tmpfs", (
                f"/tmp:rw,nosuid,nodev,noexec,size={limits.tmpfs_bytes},mode=1777"
            ),
            "--mount", f"type=volume,source={data_volume},target=/data",
            "--tmpfs", (
                "/run/vibehub:rw,nosuid,nodev,noexec,"
                f"size={SOCKET_TMPFS_BYTES},mode=0770,uid=65532,gid=65532"
            ),
            "--env", f"VIBEHUB_SOCKET={APP_SOCKET_PATH}",
            "--env", f"VIBEHUB_HEALTH_PATH={HEALTH_PATH}",
            "--env", "HOME=/data/home",
            "--env", "TMPDIR=/tmp",
            # 作品输出可能包含用户源码、答案或凭据，不得由 Docker 持久写入
            # 宿主日志。平台只记录受控的生命周期与代理元数据。
            "--log-driver", "none",
            "--stop-timeout", "1",
        ]
        args.append(image_id)
        return args

    def _stop_runtime(self, runtime_id: str, runtime: Mapping[str, object]) -> None:
        expected_name = self._container_name(runtime_id)
        if runtime.get("container_name") != expected_name:
            raise VibeHubRuntimeError("VibeHub state 中的容器名不可信")
        self.docker.remove_container(expected_name)

    def _runtime_http_request(
        self,
        container_name: str,
        method: str,
        target: str,
        headers: Mapping[str, str],
        body: bytes,
        *,
        timeout: float,
        response_max_bytes: int,
    ) -> ProxyResponse:
        return self.docker.relay_http(
            container_name,
            method,
            target,
            headers,
            body,
            timeout=timeout,
            response_max_bytes=response_max_bytes,
        )

    def _probe_runtime_health(
        self,
        container_name: str,
        *,
        timeout: float = 2.0,
    ) -> None:
        response = self._runtime_http_request(
            container_name,
            "GET",
            HEALTH_PATH,
            {"Host": "vibehub.internal", "Connection": "close"},
            b"",
            timeout=timeout,
            response_max_bytes=16 * 1024,
        )
        if response.status != 200:
            raise VibeHubProxyError("VibeHub GET /healthz 未返回 200")

    def _wait_ready(self, container_name: str, *, timeout: float = 20) -> None:
        deadline = time.monotonic() + max(1.0, float(timeout))
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                with self._health_probe_capacity_slot():
                    self._probe_runtime_health(
                        container_name,
                        timeout=min(2.0, max(0.1, deadline - time.monotonic())),
                    )
                return
            except VibeHubCapacityError:
                raise
            except (VibeHubProxyError, VibeHubRuntimeError) as exc:
                last_error = exc
            if not self.docker.container_running(container_name):
                raise VibeHubRuntimeError("VibeHub 容器在就绪前退出") from last_error
            time.sleep(0.05)
        raise VibeHubRuntimeError("VibeHub 容器健康检查超时") from last_error

    def _start_runtime(
        self,
        runtime_id: str,
        *,
        project_key: str,
        channel: str,
        image: ImageInfo,
        featured: bool,
        storage_key: str,
    ) -> dict:
        name = self._container_name(runtime_id)
        data_volume = self._data_volume_name(storage_key)
        self.docker.ensure_data_volume(
            data_volume, scope=self.scope, storage_key=storage_key,
        )
        self.docker.remove_container(name)
        try:
            self.docker.run_container(self._container_args(
                runtime_id=runtime_id,
                image_id=image.image_id,
                featured=featured,
                data_volume=data_volume,
            ))
            self.docker.verify_data_writable(name)
            self._wait_ready(name)
        except Exception:
            self.docker.remove_container(name)
            raise
        return {
            "project_key": project_key,
            "channel": channel,
            "image_ref": image.reference,
            "image_id": image.image_id,
            "featured": bool(featured),
            "container_name": name,
            "inflight": {},
        }

    def _leases_for_runtime(self, state: dict, runtime_id: str) -> list[str]:
        return [
            digest for digest, lease in state["leases"].items()
            if isinstance(lease, dict) and lease.get("runtime_id") == runtime_id
        ]

    def _remove_runtime_state(self, state: dict, runtime_id: str) -> None:
        for digest in self._leases_for_runtime(state, runtime_id):
            state["leases"].pop(digest, None)
        state["runtimes"].pop(runtime_id, None)

    def _require_runtime_capacity_locked(self, state: dict) -> None:
        """在共享 state 锁内为一个新容器预留宿主容量。"""

        # ready、starting 与 stopping 都占一个物理容器槽；reservation 先落盘再
        # docker run，保证 worker 崩溃也不会绕过跨进程上限。
        if len(state["runtimes"]) >= self.max_active_runtimes:
            raise VibeHubCapacityError(
                "VibeHub 活跃运行容器已达宿主上限，清理空闲作品后重试"
            )

    @staticmethod
    def _runtime_status(runtime: Mapping[str, object]) -> str:
        status = str(runtime.get("status") or "ready")
        if status not in {"starting", "ready", "stopping"}:
            raise VibeHubRuntimeError("VibeHub runtime status 无效")
        return status

    @staticmethod
    def _runtime_instance_key(runtime: Mapping[str, object]) -> str:
        explicit = str(runtime.get("instance_id") or "")
        if explicit:
            return explicit
        return "legacy:" + hashlib.sha256(
            (
                f"{runtime.get('container_name')}\0{runtime.get('image_id')}"
            ).encode("utf-8")
        ).hexdigest()

    def _mark_stopping_locked(
        self,
        state: dict,
        runtime_id: str,
        runtime: Mapping[str, object],
    ) -> tuple[str, str, dict]:
        operation_id = secrets.token_hex(16)
        stopping = dict(runtime)
        stopping.update({
            "status": "stopping",
            "operation_id": operation_id,
            "stop_deadline": float(self._clock()) + STOP_RESERVATION_TTL_SECONDS,
        })
        stopping.setdefault("inflight", {})
        for digest in self._leases_for_runtime(state, runtime_id):
            state["leases"].pop(digest, None)
        state["runtimes"][runtime_id] = stopping
        return runtime_id, operation_id, stopping

    def _stop_and_finalize(self, action: tuple[str, str, dict]) -> None:
        """锁外删除容器/闲置 tag，再用 operation_id 做短锁 CAS 提交。"""

        runtime_id, operation_id, runtime = action
        self._stop_runtime(runtime_id, runtime)
        image_ref = str(runtime.get("image_ref") or "")
        image_id = str(runtime.get("image_id") or "")
        if image_ref or image_id:
            if (
                not _IMAGE_REFERENCE_RE.fullmatch(image_ref)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)
            ):
                raise VibeHubRuntimeError(
                    "VibeHub stopping state 中的镜像身份无效"
                )
            # 与 build 使用相同锁序。在 tombstone/CAS 提交前保持 stopping，
            # 新 acquire 不能拿到同一实例；tag 已被新 build 更新时精确跳过。
            with self._locked_image_build(image_ref):
                with self._locked_state() as state:
                    image_still_in_use = any(
                        candidate_id != runtime_id
                        and isinstance(candidate, dict)
                        and self._runtime_status(candidate) in {"starting", "ready"}
                        and candidate.get("image_ref") == image_ref
                        and candidate.get("image_id") == image_id
                        for candidate_id, candidate in state["runtimes"].items()
                    )
                if not image_still_in_use:
                    with self._file_capacity_slot(
                        "build-slot",
                        BUILD_CONCURRENCY,
                        self.build_slot_timeout_seconds,
                    ):
                        self.docker.remove_managed_image_reference(
                            image_ref,
                            image_id,
                        )
                        self.docker.prune_managed_dangling_images()
        with self._locked_state() as state:
            current = state["runtimes"].get(runtime_id)
            if (
                isinstance(current, dict)
                and self._runtime_status(current) == "stopping"
                and current.get("operation_id") == operation_id
            ):
                state["runtimes"].pop(runtime_id, None)

    def _collect_cleanup_locked(
        self,
        state: dict,
    ) -> tuple[int, list[tuple[str, str, dict]]]:
        now = float(self._clock())
        removed = 0
        actions: list[tuple[str, str, dict]] = []
        for digest, lease in list(state["leases"].items()):
            try:
                expired = float(lease["expires_at"]) <= now
            except (KeyError, TypeError, ValueError):
                expired = True
            if expired:
                state["leases"].pop(digest, None)
                removed += 1
        for runtime_id, runtime in list(state["runtimes"].items()):
            if not _RUNTIME_ID_RE.fullmatch(runtime_id) or not isinstance(runtime, dict):
                raise VibeHubRuntimeError("VibeHub runtime state 含不可信记录")
            status = self._runtime_status(runtime)
            inflight = runtime.get("inflight")
            if not isinstance(inflight, dict):
                raise VibeHubRuntimeError("VibeHub runtime inflight state 无效")
            for request_id, expires_at in list(inflight.items()):
                try:
                    expired = float(expires_at) <= now
                except (TypeError, ValueError):
                    expired = True
                if expired:
                    inflight.pop(request_id, None)
            if status == "starting":
                try:
                    reservation_expired = float(runtime["reservation_deadline"]) <= now
                except (KeyError, TypeError, ValueError):
                    reservation_expired = True
                if reservation_expired:
                    actions.append(self._mark_stopping_locked(state, runtime_id, runtime))
                    removed += 1
            elif status == "stopping":
                try:
                    stop_expired = float(runtime["stop_deadline"]) <= now
                except (KeyError, TypeError, ValueError):
                    stop_expired = True
                if stop_expired:
                    actions.append(self._mark_stopping_locked(state, runtime_id, runtime))
            elif not self._leases_for_runtime(state, runtime_id) and not inflight:
                actions.append(self._mark_stopping_locked(state, runtime_id, runtime))
                removed += 1
        return removed, actions

    def _reconcile_once(self) -> None:
        """锁外枚举 Docker；短锁内为精确孤儿写 stopping tombstone。"""

        if self._reconciled:
            return
        with self._reconcile_once_lock:
            if self._reconciled:
                return
            candidates: list[tuple[str, str]] = []
            for name in self.docker.list_scoped_containers(self.scope):
                labels = self.docker.container_labels(name)
                if labels is None:
                    raise VibeHubRuntimeError("无法核验受管 VibeHub 容器身份")
                runtime_id = str(labels.get(RUNTIME_ID_LABEL) or "")
                if (
                    labels.get(MANAGED_CONTAINER_LABEL) != "1"
                    or labels.get(MANAGER_SCOPE_LABEL) != self.scope
                    or not _RUNTIME_ID_RE.fullmatch(runtime_id)
                    or name != self._container_name(runtime_id)
                ):
                    raise VibeHubRuntimeError(
                        "受管 label 下发现身份不一致的容器，拒绝宽泛清理"
                    )
                candidates.append((runtime_id, name))

            actions: list[tuple[str, str, dict]] = []
            with self._locked_state() as state:
                for runtime_id, name in candidates:
                    if runtime_id in state["runtimes"]:
                        continue
                    orphan = {
                        "status": "stopping",
                        "container_name": name,
                        "inflight": {},
                    }
                    actions.append(
                        self._mark_stopping_locked(state, runtime_id, orphan)
                    )
                self._reconciled = True
            for action in actions:
                self._stop_and_finalize(action)

    def _inspect_runnable_image(self, image_ref: str, *, featured: bool) -> ImageInfo:
        image = self.docker.inspect_image(image_ref)
        if image.labels.get(MANAGED_IMAGE_LABEL) != "1":
            raise VibeHubImageError("只允许运行经过离线构建器标记的 VibeHub 镜像")
        if image.volumes:
            raise VibeHubImageError("VibeHub 镜像不得声明持久化 VOLUME")
        budget = limits_for(featured).image_bytes
        if image.size_bytes > budget:
            raise VibeHubImageError(
                f"VibeHub 镜像超过 {'40' if featured else '20'} GiB 预算"
            )
        return image

    def _ensure_image(
        self,
        image_ref: str,
        *,
        build_context: Path | str | None,
        featured: bool,
    ) -> ImageInfo:
        if build_context is None:
            return self._inspect_runnable_image(image_ref, featured=featured)
        context = Path(build_context)
        _manifest, dockerfile = _manifest_and_dockerfile(context)
        bases = _dockerfile_base_images(dockerfile, self.allowed_base_images)
        context_digest, _entries, _bytes = _scan_context(context)
        resolved_bases = _inspect_build_bases(self.docker, bases)
        source_digest = _effective_source_digest(context_digest, resolved_bases)
        try:
            existing = self._inspect_runnable_image(image_ref, featured=featured)
        except VibeHubImageError:
            existing = None
        if (
            existing is not None
            and existing.labels.get(SOURCE_DIGEST_LABEL) == source_digest
            and not self._build_cleanup_is_pending()
        ):
            return existing
        with self._file_capacity_slot(
            "build-slot",
            BUILD_CONCURRENCY,
            self.build_slot_timeout_seconds,
        ):
            # 等待宿主全局构建槽期间，作品文件或管理员维护的 base tag 都可能变化；
            # 在槽内重新解析并绑定不可变 base image ID 后才允许命中缓存。
            _manifest, dockerfile = _manifest_and_dockerfile(context)
            bases = _dockerfile_base_images(dockerfile, self.allowed_base_images)
            context_digest, _entries, _bytes = _scan_context(context)
            resolved_bases = _inspect_build_bases(self.docker, bases)
            source_digest = _effective_source_digest(context_digest, resolved_bases)
            # 不同 project tag 可能在等待同一个宿主构建槽；进入后重查目标，
            # 避免另一进程已完成相同内容时重复构建。
            try:
                existing = self._inspect_runnable_image(image_ref, featured=featured)
            except VibeHubImageError:
                existing = None
            if self._build_cleanup_is_pending():
                self._cleanup_build_artifacts()
            if existing is None or existing.labels.get(SOURCE_DIGEST_LABEL) != source_digest:
                # 先落 marker 再替换稳定 tag。即使 worker 在 build 成功后崩溃，
                # 下一次缓存命中也会先补做清理，不会让 dangling layer 无限增长。
                self._mark_build_cleanup_pending()
                build_image(
                    context,
                    image_ref,
                    featured=featured,
                    allowed_base_images=self.allowed_base_images,
                    docker_client=self.docker,
                    timeout_seconds=self.build_timeout_seconds,
                    slot_timeout_seconds=self.build_slot_timeout_seconds,
                )
            image = self._inspect_runnable_image(image_ref, featured=featured)
            if image.labels.get(SOURCE_DIGEST_LABEL) != source_digest:
                raise VibeHubImageError("VibeHub 构建缓存与作品包摘要不一致")
            if self._build_cleanup_is_pending():
                self._cleanup_build_artifacts()
            return image

    def _lease_from_state(self, token: str, lease: Mapping[str, object], runtime: Mapping[str, object]) -> RuntimeLease:
        proxy_root = str(lease["proxy_root"])
        return RuntimeLease(
            token=token,
            project_key=str(lease["project_key"]),
            channel=str(lease["channel"]),
            proxy_base_path=f"{proxy_root}/{token}" if proxy_root != "/" else f"/{token}",
            expires_at=float(lease["expires_at"]),
            container_name=str(runtime["container_name"]),
            # 保留公开 dataclass 字段兼容现有调用方；该路径只存在于容器 tmpfs，
            # 绝不再映射为宿主路径。
            socket_path=Path(APP_SOCKET_PATH),
        )

    def _create_lease_locked(
        self,
        state: dict,
        runtime_id: str,
        runtime: Mapping[str, object],
        *,
        project_key: str,
        channel: str,
        proxy_root: str,
    ) -> RuntimeLease:
        if self._runtime_status(runtime) != "ready":
            raise VibeHubCapacityError("VibeHub 同版本容器正在切换，请稍后重试")
        token = self._new_token()
        lease = {
            "runtime_id": runtime_id,
            "project_key": project_key,
            "channel": channel,
            "proxy_root": proxy_root,
            "expires_at": float(self._clock()) + self.lease_ttl_seconds,
        }
        state["leases"][_token_digest(token)] = lease
        return self._lease_from_state(token, lease, runtime)

    def acquire(
        self,
        project_key: str,
        image_ref: str | None = None,
        *,
        build_context: Path | str | None = None,
        featured: bool = False,
        channel: str = "public",
        base_path: str = "/api/vibehub/runtime",
        storage_key: str,
    ) -> RuntimeLease:
        """取得短期租约；首次访问按需启动，同一版本的玩家共享一个容器。"""

        key = _validate_project_key(project_key)
        selected_channel = _validate_channel(channel)
        selected_storage_key = _validate_storage_key(
            storage_key, channel=selected_channel,
        )
        proxy_root = _validate_proxy_root(base_path)
        selected_image_ref = _validate_image_reference(
            image_ref or image_reference_for(key, channel=selected_channel)
        )
        self._reconcile_once()
        self.reap_expired()
        # 镜像构建可能持续数分钟；单独按 tag 加锁，避免把所有活跃玩家的
        # heartbeat/release 一起卡在全局 runtime state 锁后。starting reservation
        # 也必须在释放 tag 锁前落盘，否则最后一个旧 lease 的清理可能在
        # ensure_image 与 docker run 之间删掉尚未被容器 pin 的同一 image ID。
        with self._locked_image_build(selected_image_ref):
            image = self._ensure_image(
                selected_image_ref,
                build_context=build_context,
                featured=bool(featured),
            )
            runtime_id = self._runtime_id(
                key,
                selected_channel,
                image.image_id,
                bool(featured),
                selected_storage_key,
            )
            reservation_id = ""
            with self._locked_state() as state:
                runtime = state["runtimes"].get(runtime_id)
                if isinstance(runtime, dict):
                    return self._create_lease_locked(
                        state,
                        runtime_id,
                        runtime,
                        project_key=key,
                        channel=selected_channel,
                        proxy_root=proxy_root,
                    )
                if runtime is not None:
                    raise VibeHubRuntimeError(
                        "VibeHub runtime state 含不可信记录"
                    )
                self._require_runtime_capacity_locked(state)
                reservation_id = secrets.token_hex(16)
                state["runtimes"][runtime_id] = {
                    "status": "starting",
                    "reservation_id": reservation_id,
                    "reservation_deadline": (
                        float(self._clock()) + START_RESERVATION_TTL_SECONDS
                    ),
                    "project_key": key,
                    "channel": selected_channel,
                    "image_ref": image.reference,
                    "image_id": image.image_id,
                    "featured": bool(featured),
                    "container_name": self._container_name(runtime_id),
                    "inflight": {},
                }

        try:
            started = self._start_runtime(
                runtime_id,
                project_key=key,
                channel=selected_channel,
                image=image,
                featured=bool(featured),
                storage_key=selected_storage_key,
            )
        except Exception:
            action = None
            with self._locked_state() as state:
                current = state["runtimes"].get(runtime_id)
                if (
                    isinstance(current, dict)
                    and self._runtime_status(current) == "starting"
                    and current.get("reservation_id") == reservation_id
                ):
                    action = self._mark_stopping_locked(
                        state, runtime_id, current
                    )
            if action is not None:
                try:
                    self._stop_and_finalize(action)
                except Exception:
                    # 原始启动异常更接近调用方；stopping tombstone 会让 reaper
                    # 重试精确容器/tag 清理，不记录作品内容或 Docker 输出。
                    _logger.exception("VibeHub 启动失败后的资源回收未完成")
            raise

        lease_result: RuntimeLease | None = None
        expired_action = None
        with self._locked_state() as state:
            current = state["runtimes"].get(runtime_id)
            if (
                isinstance(current, dict)
                and self._runtime_status(current) == "starting"
                and current.get("reservation_id") == reservation_id
                and float(current.get("reservation_deadline") or 0)
                > float(self._clock())
            ):
                started.update({
                    "status": "ready",
                    "instance_id": reservation_id,
                })
                state["runtimes"][runtime_id] = started
                lease_result = self._create_lease_locked(
                    state,
                    runtime_id,
                    started,
                    project_key=key,
                    channel=selected_channel,
                    proxy_root=proxy_root,
                )
            elif (
                isinstance(current, dict)
                and self._runtime_status(current) == "starting"
                and current.get("reservation_id") == reservation_id
            ):
                expired_action = self._mark_stopping_locked(
                    state, runtime_id, current
                )
        if lease_result is not None:
            return lease_result
        if expired_action is not None:
            self._stop_and_finalize(expired_action)
        else:
            self._stop_runtime(runtime_id, started)
        raise VibeHubCapacityError("VibeHub 启动 reservation 已过期，请重试")

    def _lookup_lease(
        self,
        state: dict,
        token: str,
        *,
        project_key: str | None = None,
        channel: str | None = None,
    ) -> tuple[str, dict, dict]:
        digest = self._verify_token(token)
        lease = state["leases"].get(digest)
        if not isinstance(lease, dict):
            raise VibeHubLeaseError("VibeHub lease 不存在或已回收")
        try:
            expired = float(lease["expires_at"]) <= float(self._clock())
            runtime_id = str(lease["runtime_id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise VibeHubLeaseError("VibeHub lease 状态无效") from exc
        if expired:
            state["leases"].pop(digest, None)
            raise VibeHubLeaseError("VibeHub lease 已过期")
        if project_key is not None and lease.get("project_key") != _validate_project_key(project_key):
            raise VibeHubLeaseError("VibeHub lease 与作品不匹配")
        if channel is not None and lease.get("channel") != _validate_channel(channel):
            raise VibeHubLeaseError("VibeHub lease 与版本通道不匹配")
        runtime = state["runtimes"].get(runtime_id)
        if not isinstance(runtime, dict):
            raise VibeHubLeaseError("VibeHub lease 对应容器已回收")
        if self._runtime_status(runtime) != "ready":
            raise VibeHubLeaseError("VibeHub lease 对应容器正在回收")
        return digest, lease, runtime

    def heartbeat(
        self,
        token: str,
        *,
        project_key: str | None = None,
        channel: str | None = None,
    ) -> RuntimeLease:
        self._reconcile_once()
        with self._locked_state() as state:
            _digest, lease, runtime = self._lookup_lease(
                state, token, project_key=project_key, channel=channel,
            )
            runtime_id = str(lease["runtime_id"])
            container_name = self._container_name(runtime_id)
            instance_key = self._runtime_instance_key(runtime)

        try:
            with self._health_probe_capacity_slot():
                if (
                    runtime.get("container_name") != container_name
                    or not self.docker.container_running(container_name)
                ):
                    raise VibeHubRuntimeError("VibeHub heartbeat 发现容器未运行")
                self._probe_runtime_health(
                    container_name,
                    timeout=min(2.0, self.request_timeout_seconds),
                )
        except VibeHubCapacityError:
            # 容量拒绝不是作品故障：不续租、不 poison、不触碰容器，路由映射 429。
            raise
        except (VibeHubRuntimeError, VibeHubProxyError) as exc:
            action = None
            with self._locked_state() as state:
                current = state["runtimes"].get(runtime_id)
                if (
                    isinstance(current, dict)
                    and self._runtime_status(current) == "ready"
                    and self._runtime_instance_key(current) == instance_key
                ):
                    action = self._mark_stopping_locked(
                        state, runtime_id, current
                    )
            if action is not None:
                self._stop_and_finalize(action)
            raise VibeHubRuntimeError(
                "VibeHub heartbeat 健康检查失败，运行实例已回收"
            ) from exc

        with self._locked_state() as state:
            digest, lease, current = self._lookup_lease(
                state, token, project_key=project_key, channel=channel,
            )
            if self._runtime_instance_key(current) != instance_key:
                raise VibeHubLeaseError("VibeHub lease 对应运行实例已切换")
            lease["expires_at"] = float(self._clock()) + self.lease_ttl_seconds
            state["leases"][digest] = lease
            return self._lease_from_state(token, lease, current)

    def validate_proxy_capability(
        self,
        token: str,
        *,
        project_key: str | None = None,
        channel: str | None = None,
    ) -> None:
        """只校验代理 capability；供宿主本地回答 CORS 预检。

        预检不得进入不可信容器，也不应占用健康检查/代理容量槽。实际请求仍会在
        ``proxy`` 中重新校验 lease 并确认容器状态，避免校验与使用之间的竞态。
        """

        # 签名检查必须先于 state 文件 I/O，伪造 token 不能制造共享锁竞争。
        self._verify_token(token)
        with self._locked_state() as state:
            self._lookup_lease(
                state,
                token,
                project_key=project_key,
                channel=channel,
            )

    def release(
        self,
        token: str,
        *,
        project_key: str | None = None,
        channel: str | None = None,
    ) -> bool:
        """释放租约；最后一位玩家且无进行中请求时立刻 ``docker rm -f``。"""

        self._reconcile_once()
        action = None
        with self._locked_state() as state:
            try:
                digest, lease, runtime = self._lookup_lease(
                    state, token, project_key=project_key, channel=channel,
                )
            except VibeHubLeaseError:
                # release/pagehide 必须幂等；伪造 token 仍会在签名校验阶段失败。
                self._verify_token(token)
                return False
            runtime_id = str(lease["runtime_id"])
            state["leases"].pop(digest, None)
            inflight = runtime.get("inflight") or {}
            if not self._leases_for_runtime(state, runtime_id) and not inflight:
                action = self._mark_stopping_locked(state, runtime_id, runtime)
        if action is not None:
            self._stop_and_finalize(action)
        return True

    def reap_expired(self) -> int:
        self._reconcile_once()
        with self._locked_state() as state:
            removed, actions = self._collect_cleanup_locked(state)
        first_error: Exception | None = None
        for action in actions:
            try:
                self._stop_and_finalize(action)
            except Exception as exc:
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error
        return removed

    def _reaper_loop(self) -> None:
        while not self._reaper_stop.wait(self.reaper_interval_seconds):
            try:
                self.reap_expired()
            except Exception:
                # 不包含 token、project 内容或 Docker 输出；具体失败会在下一轮重试。
                _logger.exception("VibeHub 后台容器回收失败")

    def start_reaper(self) -> None:
        """显式启动进程内 daemon；共享 flock 保证多 worker 不会并发清理。"""

        with self._thread_lock:
            if self._reaper_thread is not None and self._reaper_thread.is_alive():
                return
            self._reaper_stop.clear()
            thread = threading.Thread(
                target=self._reaper_loop,
                name=f"vibehub-reaper-{self.scope}",
                daemon=True,
            )
            self._reaper_thread = thread
            thread.start()

    def stop_reaper(self, *, timeout: float = 2.0) -> None:
        """停止本进程线程；不碰共享容器，避免杀死其它 worker 的玩家。"""

        with self._thread_lock:
            thread = self._reaper_thread
            self._reaper_stop.set()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, float(timeout)))
        with self._thread_lock:
            if self._reaper_thread is thread and (thread is None or not thread.is_alive()):
                self._reaper_thread = None

    def proxy(
        self,
        token: str,
        method: str,
        path: str,
        headers: Mapping[str, str] | Sequence[tuple[str, str]],
        body: bytes = b"",
        *,
        project_key: str | None = None,
        channel: str | None = None,
    ) -> ProxyResponse:
        payload = bytes(body or b"")
        if len(payload) > self.request_max_bytes:
            raise VibeHubRequestTooLarge("VibeHub 请求体超过代理上限")
        return self._proxy_with_body_loader(
            token,
            method,
            path,
            headers,
            lambda: payload,
            project_key=project_key,
            channel=channel,
        )

    def proxy_from_reader(
        self,
        token: str,
        method: str,
        path: str,
        headers: Mapping[str, str] | Sequence[tuple[str, str]],
        body_reader: Callable[[int], bytes],
        *,
        project_key: str | None = None,
        channel: str | None = None,
    ) -> ProxyResponse:
        """先验证 capability 并取得共享槽，再从 WSGI 流限量读取 body。"""

        if not callable(body_reader):
            raise VibeHubProxyError("VibeHub 请求体读取器无效")

        def load_body() -> bytes:
            try:
                raw = body_reader(self.request_max_bytes + 1)
            except Exception as exc:
                raise VibeHubProxyError("VibeHub 请求体读取失败") from exc
            if not isinstance(raw, (bytes, bytearray, memoryview)):
                raise VibeHubProxyError("VibeHub 请求体读取结果无效")
            payload = bytes(raw)
            if len(payload) > self.request_max_bytes:
                raise VibeHubRequestTooLarge("VibeHub 请求体超过代理上限")
            return payload

        return self._proxy_with_body_loader(
            token,
            method,
            path,
            headers,
            load_body,
            project_key=project_key,
            channel=channel,
        )

    def _proxy_with_body_loader(
        self,
        token: str,
        method: str,
        path: str,
        headers: Mapping[str, str] | Sequence[tuple[str, str]],
        body_loader: Callable[[], bytes],
        *,
        project_key: str | None,
        channel: str | None,
    ) -> ProxyResponse:
        selected_method = str(method or "").upper()
        if selected_method not in _ALLOWED_METHODS:
            raise VibeHubProxyError("VibeHub 代理方法不受支持")
        target = _safe_request_target(path)

        # 容量等待前先验证 capability 与共享 lease，避免伪造请求占满代理槽位。
        self._verify_token(token)
        self._reconcile_once()
        with self._locked_state() as state:
            _digest, lease, runtime = self._lookup_lease(
                state, token, project_key=project_key, channel=channel,
            )
            base_path = self._lease_from_state(token, lease, runtime).proxy_base_path
        clean_headers = _sanitize_request_headers(
            headers,
            base_path=base_path,
            session_id=self._session_id_for_token(token),
        )

        with self._proxy_capacity_slot():
            # WSGI 流必须到这里才读取：无效 token 或已满的共享槽都不能让
            # 未授权大 body 占据每个 Gunicorn gthread 的内存。
            payload = body_loader()
            request_id = secrets.token_hex(16)
            runtime_id = ""
            container_name = ""
            instance_key = ""
            with self._locked_state() as state:
                digest, lease, runtime = self._lookup_lease(
                    state, token, project_key=project_key, channel=channel,
                )
                lease["expires_at"] = float(self._clock()) + self.lease_ttl_seconds
                state["leases"][digest] = lease
                runtime_id = str(lease["runtime_id"])
                container_name = self._container_name(runtime_id)
                instance_key = self._runtime_instance_key(runtime)
                inflight = runtime.setdefault("inflight", {})
                if not isinstance(inflight, dict):
                    raise VibeHubRuntimeError("VibeHub runtime inflight state 无效")
                inflight[request_id] = (
                    float(self._clock()) + self.request_timeout_seconds + 10
                )

            poison_runtime = False
            try:
                if not self.docker.container_running(container_name):
                    raise VibeHubProxyError("VibeHub 代理发现容器未运行")
                raw_response = self._runtime_http_request(
                    container_name,
                    selected_method,
                    target,
                    clean_headers,
                    payload,
                    timeout=self.request_timeout_seconds,
                    response_max_bytes=self.response_max_bytes,
                )
                return _sanitize_response(
                    raw_response,
                    base_path=base_path,
                    request_target=target,
                )
            except (VibeHubProxyError, VibeHubRuntimeError):
                # exec timeout/畸形 relay frame 可能留下容器内进程；HTTP 协议或 socket
                # 状态异常同样说明实例不再可信。整实例回收比尝试复用更安全。
                poison_runtime = True
                raise
            finally:
                action = None
                with self._locked_state() as state:
                    runtime = state["runtimes"].get(runtime_id)
                    same_instance = (
                        isinstance(runtime, dict)
                        and self._runtime_status(runtime) == "ready"
                        and self._runtime_instance_key(runtime) == instance_key
                    )
                    if same_instance and poison_runtime:
                        action = self._mark_stopping_locked(
                            state, runtime_id, runtime
                        )
                    elif same_instance:
                        inflight = runtime.get("inflight")
                        if isinstance(inflight, dict):
                            inflight.pop(request_id, None)
                        if not self._leases_for_runtime(state, runtime_id) and not inflight:
                            action = self._mark_stopping_locked(
                                state, runtime_id, runtime
                            )
                if action is not None:
                    self._stop_and_finalize(action)


_default_manager: VibeHubRuntimeManager | None = None
_default_manager_lock = threading.Lock()
_registered_manager_kwargs: dict | None = None


def _config_value(source, name: str, default):
    if isinstance(source, Mapping):
        return source.get(name, default)
    return getattr(source, name, default)


def _manager_kwargs_from_config(config_source) -> dict:
    """只解析并校验配置，不创建目录、线程或 Docker 连接。"""

    raw_root_value = str(_config_value(
        config_source,
        "VIBEHUB_RUNTIME_ROOT",
        os.fspath(DEFAULT_RUNTIME_ROOT),
    ) or "").strip()
    if not raw_root_value:
        raise ValueError("VIBEHUB_RUNTIME_ROOT 不能为空")
    raw_root = Path(raw_root_value)
    selected_root = raw_root if raw_root.is_absolute() else PROJECT_ROOT / raw_root
    resolved_root = selected_root.resolve(strict=False)
    if resolved_root in {Path("/"), PROJECT_ROOT.resolve()} or len(resolved_root.parts) < 3:
        raise ValueError("VIBEHUB_RUNTIME_ROOT 不能指向宽泛系统或项目根目录")
    allowed = _config_value(
        config_source,
        "VIBEHUB_ALLOWED_BASE_IMAGES",
        [DEFAULT_BASE_IMAGE],
    )
    if not isinstance(allowed, (list, tuple)) or not allowed or not all(
        isinstance(item, str) and item.strip() for item in allowed
    ):
        raise ValueError("VIBEHUB_ALLOWED_BASE_IMAGES 必须是非空字符串数组")
    normalized_allowed = tuple(_validate_image_reference(item.strip()) for item in allowed)
    build_builder = str(_config_value(
        config_source, "VIBEHUB_BUILD_BUILDER", "",
    ) or "").strip()
    if build_builder and not _DOCKER_NAME_RE.fullmatch(build_builder):
        raise ValueError("VIBEHUB_BUILD_BUILDER 名称无效")
    require_dedicated_builder = _config_value(
        config_source, "VIBEHUB_REQUIRE_DEDICATED_BUILDER", False,
    )
    if type(require_dedicated_builder) is not bool:
        raise ValueError("VIBEHUB_REQUIRE_DEDICATED_BUILDER 必须是布尔值")
    raw_oci_root_value = str(_config_value(
        config_source,
        "VIBEHUB_BASE_OCI_LAYOUT_ROOT",
        os.fspath(DEFAULT_BASE_OCI_LAYOUT_ROOT),
    ) or "").strip()
    if not raw_oci_root_value:
        raise ValueError("VIBEHUB_BASE_OCI_LAYOUT_ROOT 不能为空")
    raw_oci_root = Path(raw_oci_root_value)
    selected_oci_root = (
        raw_oci_root if raw_oci_root.is_absolute() else PROJECT_ROOT / raw_oci_root
    )
    resolved_oci_root = selected_oci_root.resolve(strict=False)
    if (
        resolved_oci_root in {Path("/"), PROJECT_ROOT.resolve()}
        or len(resolved_oci_root.parts) < 3
    ):
        raise ValueError(
            "VIBEHUB_BASE_OCI_LAYOUT_ROOT 不能指向宽泛系统或项目根目录"
        )
    kwargs = {
        "runtime_root": selected_root,
        "allowed_base_images": normalized_allowed,
        "lease_ttl_seconds": float(_config_value(
            config_source, "VIBEHUB_LEASE_TTL_SECONDS", DEFAULT_LEASE_TTL_SECONDS,
        )),
        "reaper_interval_seconds": float(_config_value(
            config_source, "VIBEHUB_REAPER_INTERVAL_SECONDS", 15.0,
        )),
        "request_timeout_seconds": float(_config_value(
            config_source,
            "VIBEHUB_REQUEST_TIMEOUT_SECONDS",
            DEFAULT_REQUEST_TIMEOUT_SECONDS,
        )),
        "request_max_bytes": int(_config_value(
            config_source, "VIBEHUB_REQUEST_MAX_BYTES", DEFAULT_REQUEST_MAX_BYTES,
        )),
        "response_max_bytes": int(_config_value(
            config_source, "VIBEHUB_RESPONSE_MAX_BYTES", DEFAULT_RESPONSE_MAX_BYTES,
        )),
        "proxy_transport": str(_config_value(
            config_source, "VIBEHUB_PROXY_TRANSPORT", "docker-exec",
        ) or "docker-exec"),
        "build_timeout_seconds": float(_config_value(
            config_source,
            "VIBEHUB_BUILD_TIMEOUT_SECONDS",
            DEFAULT_BUILD_TIMEOUT_SECONDS,
        )),
        "build_slot_timeout_seconds": float(_config_value(
            config_source,
            "VIBEHUB_BUILD_SLOT_TIMEOUT_SECONDS",
            DEFAULT_BUILD_SLOT_TIMEOUT_SECONDS,
        )),
        "proxy_slot_timeout_seconds": float(_config_value(
            config_source,
            "VIBEHUB_PROXY_SLOT_TIMEOUT_SECONDS",
            DEFAULT_PROXY_SLOT_TIMEOUT_SECONDS,
        )),
        "health_probe_slot_timeout_seconds": float(_config_value(
            config_source,
            "VIBEHUB_HEALTH_PROBE_SLOT_TIMEOUT_SECONDS",
            DEFAULT_HEALTH_PROBE_SLOT_TIMEOUT_SECONDS,
        )),
        "max_active_runtimes": _validated_max_active_runtimes(_config_value(
            config_source,
            "VIBEHUB_MAX_ACTIVE_RUNTIMES",
            DEFAULT_MAX_ACTIVE_RUNTIMES,
        )),
        "build_builder": build_builder,
        "require_dedicated_builder": require_dedicated_builder,
        "build_cache_max_bytes": _validated_build_cache_max_bytes(_config_value(
            config_source,
            "VIBEHUB_BUILD_CACHE_MAX_BYTES",
            DEFAULT_BUILD_CACHE_MAX_BYTES,
        )),
        "base_oci_layout_root": selected_oci_root,
    }
    lease_ttl = kwargs["lease_ttl_seconds"]
    reaper_interval = kwargs["reaper_interval_seconds"]
    request_timeout = kwargs["request_timeout_seconds"]
    if not math.isfinite(lease_ttl) or not 10 <= lease_ttl <= 3600:
        raise ValueError("VIBEHUB_LEASE_TTL_SECONDS 必须在 10–3600 之间")
    if not math.isfinite(reaper_interval) or not 0.05 <= reaper_interval < lease_ttl:
        raise ValueError("VIBEHUB_REAPER_INTERVAL_SECONDS 必须小于 lease TTL")
    if not math.isfinite(request_timeout) or not 0.1 <= request_timeout <= 120:
        raise ValueError("VIBEHUB_REQUEST_TIMEOUT_SECONDS 必须在 0.1–120 之间")
    if not (
        0 < kwargs["request_max_bytes"] <= _PROXY_BODY_HARD_MAX_BYTES
        and 0 < kwargs["response_max_bytes"] <= _PROXY_BODY_HARD_MAX_BYTES
    ):
        raise ValueError("VibeHub 请求/响应上限必须在 1–64 MiB 之间")
    if kwargs["proxy_transport"].strip().lower() not in {"auto", "docker-exec"}:
        raise ValueError(
            "VIBEHUB_PROXY_TRANSPORT 只允许 docker-exec；host-uds 已禁用"
        )
    _validated_build_timeout_seconds(kwargs["build_timeout_seconds"])
    if not (
        math.isfinite(kwargs["build_slot_timeout_seconds"])
        and 0 <= kwargs["build_slot_timeout_seconds"] <= 120
    ):
        raise ValueError("VIBEHUB_BUILD_SLOT_TIMEOUT_SECONDS 必须在 0–120 之间")
    if not (
        math.isfinite(kwargs["proxy_slot_timeout_seconds"])
        and 0 <= kwargs["proxy_slot_timeout_seconds"] <= 10
    ):
        raise ValueError("VIBEHUB_PROXY_SLOT_TIMEOUT_SECONDS 必须在 0–10 之间")
    if not (
        math.isfinite(kwargs["health_probe_slot_timeout_seconds"])
        and 0 <= kwargs["health_probe_slot_timeout_seconds"] <= 5
    ):
        raise ValueError(
            "VIBEHUB_HEALTH_PROBE_SLOT_TIMEOUT_SECONDS 必须在 0–5 秒之间"
        )
    if kwargs["require_dedicated_builder"] and not kwargs["build_builder"]:
        raise ValueError(
            "要求专属 builder 时 VIBEHUB_BUILD_BUILDER 不能为空"
        )
    environment = str(_config_value(
        config_source,
        "NUMOJ_ENVIRONMENT",
        os.environ.get("NUMOJ_ENVIRONMENT", "development"),
    ) or "development").strip().lower()
    if environment == "production":
        if (
            not kwargs["require_dedicated_builder"]
            or not kwargs["build_builder"]
        ):
            raise ValueError(
                "production 必须配置并要求 VibeHub 专属 docker-container builder"
            )
    return kwargs


def register_runtime_manager_config(config_source) -> None:
    """组合根的惰性注册入口；可以安全地在 Web/Celery import ``oj`` 时调用。"""

    global _registered_manager_kwargs
    kwargs = _manager_kwargs_from_config(config_source)
    with _default_manager_lock:
        if _default_manager is not None:
            raise VibeHubRuntimeError("VibeHub runtime manager 已初始化，不能重新注册配置")
        if _registered_manager_kwargs is not None and _registered_manager_kwargs != kwargs:
            raise VibeHubRuntimeError("VibeHub runtime manager 配置已注册")
        _registered_manager_kwargs = kwargs


def configure_runtime_manager(
    config_source,
    *,
    docker_client: DockerCLI | None = None,
    start_reaper: bool = True,
) -> VibeHubRuntimeManager:
    """显式立即初始化入口；应用组合根应优先使用惰性 ``register``。"""

    global _default_manager
    kwargs = _manager_kwargs_from_config(config_source)
    manager = VibeHubRuntimeManager(docker_client=docker_client, **kwargs)
    with _default_manager_lock:
        if _default_manager is not None:
            raise VibeHubRuntimeError("VibeHub runtime manager 已初始化")
        _default_manager = manager
    if start_reaper:
        manager.start_reaper()
    return manager


def get_runtime_manager() -> VibeHubRuntimeManager:
    """延迟构造进程内 facade；跨进程真相仍由 runtime_root 锁和 state 维护。"""

    global _default_manager
    if _default_manager is None:
        with _default_manager_lock:
            if _default_manager is None:
                kwargs = dict(_registered_manager_kwargs or {})
                _default_manager = VibeHubRuntimeManager(**kwargs)
                _default_manager.start_reaper()
    return _default_manager


def ensure_vibehub_runtime_reaper() -> VibeHubRuntimeManager:
    """Web 进程启动时幂等创建 manager 并确保后台回收线程存活。"""

    manager = get_runtime_manager()
    manager.start_reaper()
    return manager


def shutdown_runtime_manager(*, reset_config: bool = False) -> None:
    """停止默认 reaper，供进程关闭和测试使用；不会清除共享 lease。"""

    global _default_manager, _registered_manager_kwargs
    with _default_manager_lock:
        manager = _default_manager
        _default_manager = None
        if reset_config:
            _registered_manager_kwargs = None
    if manager is not None:
        manager.stop_reaper()


__all__ = [
    "APP_SOCKET_PATH",
    "DEFAULT_BASE_IMAGE",
    "DEFAULT_MAX_ACTIVE_RUNTIMES",
    "DockerCLI",
    "FEATURED_IMAGE_BYTES",
    "HEALTH_PATH",
    "ImageBuildResult",
    "ImageInfo",
    "ProxyResponse",
    "RUNTIME_CORS_METHODS",
    "RUNTIME_CORS_REQUEST_HEADERS",
    "RuntimeLease",
    "RuntimeLimits",
    "STANDARD_IMAGE_BYTES",
    "VibeHubCapacityError",
    "VibeHubImageError",
    "VibeHubLeaseError",
    "VibeHubPackageError",
    "VibeHubProxyError",
    "VibeHubRequestTooLarge",
    "VibeHubRuntimeError",
    "VibeHubRuntimeManager",
    "build_image",
    "configure_runtime_manager",
    "ensure_vibehub_runtime_reaper",
    "get_runtime_manager",
    "image_reference_for",
    "limits_for",
    "register_runtime_manager_config",
    "shutdown_runtime_manager",
]
