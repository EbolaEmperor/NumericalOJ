"""Typed bridge for deployment keys and environment-overridable code defaults."""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
import re


_ROOT = Path(__file__).resolve().parent
_ENV_TEMPLATE_PATH = _ROOT / ".env.tmpl"
_ENV_PATH = _ROOT / ".env"
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _strip_inline_comment(value: str, *, path: Path, line_number: int) -> str:
    """Strip whitespace-prefixed comments without interpreting shell syntax."""
    quote = None
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if quote == '"' and character == "\\":
            escaped = True
            continue
        if character in {'"', "'"}:
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
            continue
        if character == "#" and quote is None:
            if index == 0 or value[index - 1].isspace():
                return value[:index].rstrip()
    if quote is not None:
        raise ValueError(f"{path}:{line_number}: 配置值引号未闭合")
    return value.strip()


def _read_env_file(
    path: Path,
    *,
    required: bool,
    accepted_keys: set[str] | frozenset[str] | None = None,
) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        if required:
            raise RuntimeError(f"缺少配置模板文件: {path}")
        return {}

    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            raise ValueError(f"{path}:{line_number}: 配置行缺少等号")
        key, value = line.split("=", 1)
        key = key.strip()
        if not _ENV_KEY_RE.fullmatch(key):
            raise ValueError(f"{path}:{line_number}: 非法配置名 {key!r}")
        if accepted_keys is not None and key not in accepted_keys:
            continue
        if key in values:
            raise ValueError(f"{path}:{line_number}: 重复配置项 {key}")
        values[key] = _strip_inline_comment(
            value.strip(),
            path=path,
            line_number=line_number,
        )
    return values


def _decode_value(raw_value: str, *, name: str = ""):
    text = str(raw_value).strip()
    if text.startswith("'") or text.endswith("'"):
        if len(text) < 2 or not (text[0] == text[-1] == "'"):
            raise ValueError(f"配置项 {name or '<unknown>'} 的引号格式无效")
        return text[1:-1]
    if text.startswith('"') or text.endswith('"'):
        try:
            value = json.loads(text)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"配置项 {name or '<unknown>'} 的 JSON 字符串格式无效"
            ) from exc
        if not isinstance(value, str):
            raise ValueError(f"配置项 {name or '<unknown>'} 必须是字符串")
        return value
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return text


def _environment_text(raw_value: str, *, name: str) -> str:
    value = _decode_value(raw_value, name=name)
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


_REQUIRED_ENV_KEYS = frozenset(
    {
        "SECRET_KEY",
        "MYSQL_HOST",
        "MYSQL_PORT",
        "MYSQL_DB",
        "MYSQL_USERNAME",
        "MYSQL_PASSWORD",
        "REDIS_HOST",
        "REDIS_PORT",
        "REDIS_DB",
    }
)

# 高级运行参数保留环境变量覆盖能力，但不再挤占部署必填模板。这里的值
# 使用与 .env 相同的原始文本格式，所有类型仍由下方的 _env_* 桥接函数校验。
# LLM、Embedding、SMTP 与 WebSearch 等业务配置必须从 MySQL 动态读取，不能
# 在这里添加默认值或环境变量回退。
_CODE_DEFAULTS: dict[str, str] = {
    "FLASK_DEBUG": "false",
    "SESSION_COOKIE_SECURE": "false",
    "CONTENT_SECURITY_POLICY": '""',
    "CSRF_TRUSTED_ORIGINS": "[]",
    "LOG_LEVEL": '"INFO"',
    "LOG_TRUSTED_PROXY_CIDRS": "[]",
    "MYSQL_CONNECT_TIMEOUT": "5",
    "MYSQL_POOL_MIN_SIZE": "2",
    "MYSQL_POOL_MAX_SIZE": "6",
    "MYSQL_POOL_WAIT_TIMEOUT": "3",
    "MYSQL_POOL_RECYCLE_SECONDS": "1200",
    "AI_CODE_MARKS_IMAGE_ANALYSIS_TIMEOUT": "180",
    "REDIS_SOCKET_TIMEOUT_SECONDS": "3",
    "REDIS_CONNECT_TIMEOUT_SECONDS": "3",
    "REDIS_BLOCKING_SOCKET_TIMEOUT_SECONDS": "30",
    "SUBMISSION_SNAPSHOT_TTL_SECONDS": "21600",
    "EVALUATE_SUBMISSION_LOCK_TTL_SECONDS": "900",
    "REPOSITORY_STORAGE_ROOT": '"repository_storage"',
    "REPOSITORY_MAX_FILE_BYTES": "2097152",
    "REPOSITORY_MAX_TOTAL_BYTES": "33554432",
    "REPOSITORY_MAX_ENTRIES": "10000",
    "REPOSITORY_MAX_DEPTH": "32",
    "REPOSITORY_MAX_PATH_BYTES": "1024",
    "REPOSITORY_UPLOAD_SESSION_TTL_SECONDS": "86400",
    "REPOSITORY_EMBEDDING_DIM": "1024",
    "REPOSITORY_STRUCTURED_TIMEOUT": "240",
    "REPOSITORY_STRUCTURED_MAX_INPUT_CHARS": "120000",
    "REPOSITORY_EMBEDDING_TIMEOUT": "120",
    "REPOSITORY_EMBEDDING_BATCH_SIZE": "16",
    "REPOSITORY_VECTOR_BACKEND": '"faiss"',
    "REPOSITORY_FAISS_INDEX_ROOT": '"tmp/repository_vector_index"',
    "LATEX_OCR_MAX_IMAGES_PER_REQUEST": "20",
    "LATEX_OCR_STREAM_EMIT_INTERVAL": "0.6",
    "LATEX_OCR_STREAM_EMIT_MIN_DELTA": "60",
    "AGENT_MAX_ROUNDS": "32",
    "AGENT_SUBMIT_LIMIT": "8",
    "AGENT_MEMORY_ENABLED": "true",
    "AGENT_CONTEXT_MAX_CHARS": "480000",
    "AGENT_CONTEXT_KEEP_ROUNDS": "50",
    "AGENT_MEMORY_MAX_PATTERNS": "24",
    "AGENT_MEMORY_MAX_NOTES": "24",
    "AGENT_MEMORY_MAX_DO_NOT_REPEAT": "24",
    "AGENT_REPOSITORY_KNN_TOP_K": "5",
    "AGENT_REPOSITORY_KNN_SCORE_THRESHOLD": "0.08",
    "AGENT_CONTEXT_SUMMARY_TIMEOUT": "120",
    "AGENT_CONTEXT_SUMMARY_INPUT_MAX_CHARS": "480000",
    "AGENT_CONTEXT_SUMMARY_OUTPUT_MAX_CHARS": "48000",
    "MODELSCOPE_WEB_SEARCH_TIMEOUT_SECONDS": "90",
    "AGENT_JUDGE_DOCKER_IMAGE": '"numericaloj-agent-judge:latest"',
    "AGENT_JUDGE_WORKSPACE_ROOT": '"ranking_uploads/judge_workspace"',
    "AGENT_JUDGE_CONCURRENCY": "2",
    "AGENT_JUDGE_DEFAULT_TIMEOUT": "1800",
    "AGENT_JUDGE_MEM_LIMIT": '"4g"',
    "AGENT_JUDGE_CPU_LIMIT": '"2"',
    "AGENT_JUDGE_PIDS_LIMIT": '"512"',
    "AGENT_JUDGE_RESULT_POLL_INTERVAL": "1.5",
    "AGENT_JUDGE_PROGRESS_TTL": "21600",
    "JUDGER_DOCKER_IMAGE": '"numericaloj-judger:latest"',
    "JUDGER_DOCKER_MEM_LIMIT": '"1g"',
    "JUDGER_DOCKER_CPU_LIMIT": '"2"',
    "JUDGER_DOCKER_PIDS_LIMIT": '"128"',
    "JUDGER_DOCKER_NETWORK": '"none"',
    "JUDGER_DOCKER_RUNNER_UID": "65532",
    "JUDGER_DOCKER_RUNNER_GID": "65532",
    "JUDGER_DOCKER_CASE_TMPFS_BYTES": "134217728",
    "JUDGER_DOCKER_EXPORT_TMPFS_BYTES": "100663296",
    "JUDGER_CASE_INPUT_MAX_BYTES": "67108864",
    "JUDGER_STDOUT_MAX_BYTES": "1048576",
    "JUDGER_STDERR_MAX_BYTES": "1048576",
    "OJ_ROOT_PATH": '""',
    "JUDGER_RUN_ROOT": '""',
    "JUDGER_TIMEOUT_KILL_AFTER_SEC": "1.0",
    "JUDGER_OCTAVE_PLOT_WARMUP": "true",
    "JUDGER_TARGET_ARCH": '""',
    "JUDGER_NUMERIC_BACKEND": '""',
    "JUDGER_ENABLE_MKL": '""',
    "AGENT_JUDGE_TRACE_SYNC_INTERVAL_SECONDS": "5.0",
    "AGENT_JUDGE_QUEUE_RETRY_SECONDS": "8",
    "AGENT_JUDGE_MAX_QUEUE_RETRIES": "2000",
    "AGENT_JUDGE_SLOT_TTL_BUFFER": "600",
    "AGENT_JUDGE_PACKAGE_MAX_MEMBERS": "4096",
    "AGENT_JUDGE_PACKAGE_MAX_FILE_BYTES": "268435456",
    "AGENT_JUDGE_PACKAGE_MAX_TOTAL_BYTES": "536870912",
    "AGENT_JUDGE_PACKAGE_MAX_COMPRESSION_RATIO": "500.0",
    "AGENT_JUDGE_HELLO_TIMEOUT_SECONDS": "8.0",
    "AGENT_JUDGE_HELLO_RETRY_SLEEP_SECONDS": "1.0",
    "AGENT_JUDGE_PAUSED_PROBE_INTERVAL_SECONDS": "3600",
    "AGENT_JUDGE_OPENCODE_HELLO_TIMEOUT_SECONDS": "30.0",
    "TESTDATA_ZIP_MAX_MEMBERS": "4096",
    "TESTDATA_ZIP_MAX_FILE_BYTES": "134217728",
    "TESTDATA_ZIP_MAX_TOTAL_BYTES": "268435456",
    "TESTDATA_ZIP_MAX_COMPRESSION_RATIO": "500.0",
    "TESTDATA_TEXT_MAX_TOTAL_BYTES": "67108864",
    "RANKING_BATCH_LSREMOTE_TIMEOUT": "20",
    "RANKING_BATCH_CLONE_TIMEOUT": "180",
    "RANKING_BATCH_PROBE_CONCURRENCY": "12",
    "RANKING_BATCH_PROBE_MAX_USERS": "1000",
    "RANKING_BATCH_CLONE_ZIP_MAX_BYTES": "134217728",
    "RANKING_BATCH_JOB_TTL": "21600",
    "RANKING_BATCH_PULL_RETRY": "3",
    "RANKING_BATCH_CREATE_RETRY": "3",
    "RANKING_BATCH_ITEM_SLEEP_SECONDS": "1.0",
    "RANKING_BULK_REJUDGE_JOB_TTL": "21600",
    "RANKING_BULK_REJUDGE_ITEM_SLEEP_SECONDS": "2.0",
    "REVERSE_JUDGE_PROGRESS_TTL": "21600",
    "REVERSE_JUDGE_WORKSPACE_ROOT": '"ranking_uploads/reverse_judge_workspace"',
    "REVERSE_JUDGE_SCRIPT_TIMEOUT": "300",
    "REVERSE_JUDGE_TRACE_SYNC_INTERVAL": "2.0",
    "REVERSE_JUDGE_STREAM_TIMEOUT_BUFFER_SECONDS": "1200",
    "REVERSE_QUALITY_GATE_TIMEOUT_SECONDS": "300",
    "REVERSE_QUALITY_GATE_MAX_PROMPT_CHARS": "20000",
    "REVERSE_QUALITY_GATE_RESULT_MAX_BYTES": "2097152",
    "REVERSE_PACKAGE_MAX_MEMBERS": "4096",
    "REVERSE_PACKAGE_MAX_FILE_BYTES": "268435456",
    "REVERSE_PACKAGE_MAX_TOTAL_BYTES": "536870912",
    "REVERSE_PACKAGE_MAX_COMPRESSION_RATIO": "500.0",
    "REVERSE_ANSWER_MAX_FILES": "4096",
    "REVERSE_ANSWER_MAX_FILE_BYTES": "268435456",
    "REVERSE_ANSWER_MAX_TOTAL_BYTES": "536870912",
    "REVERSE_ENDPOINT_PROXY_MAX_REQUEST_BYTES": "8388608",
    "REVERSE_ENDPOINT_PROXY_MAX_CONNECTIONS": "2",
    "REVERSE_ENDPOINT_PROXY_CLIENT_TIMEOUT_SECONDS": "30",
    "REVERSE_ENDPOINT_PROXY_TIMEOUT_SECONDS": "600",
    "REVERSE_ENDPOINT_PROXY_BIND_HOST": '"0.0.0.0"',
    "REVERSE_ENDPOINT_PROXY_CONTAINER_HOST": '"host.docker.internal"',
    "REVERSE_TRACE_RETENTION_SECONDS": "1209600",
    "REVERSE_TRACE_MAX_ATTEMPTS": "8",
    "REVERSE_TRACE_MIN_DELETE_AGE_SECONDS": "21600",
}

_template_values = _read_env_file(_ENV_TEMPLATE_PATH, required=True)
if frozenset(_template_values) != _REQUIRED_ENV_KEYS:
    raise RuntimeError(".env.tmpl 必须且只能包含九项部署必填配置")
_declared_keys = _REQUIRED_ENV_KEYS | _CODE_DEFAULTS.keys()
_local_values = _read_env_file(
    _ENV_PATH,
    required=False,
    accepted_keys=set(_declared_keys),
)
_process_values = dict(os.environ)
_config_values = dict(_CODE_DEFAULTS)
_config_values.update(_template_values)
_config_values.update(_local_values)
for _key in tuple(_config_values):
    if _key in _process_values:
        _config_values[_key] = _process_values[_key]
    else:
        os.environ[_key] = _environment_text(_config_values[_key], name=_key)

ENV_FILE_LOADED = _ENV_PATH.is_file()
ENV_FILE_KEYS = frozenset(_local_values)


def _raw(name: str) -> str:
    try:
        return _config_values[name]
    except KeyError as exc:
        raise RuntimeError(f"配置项未声明: {name}") from exc


def _env_str(name: str) -> str:
    if name in _process_values:
        return str(_raw(name))
    value = _decode_value(_raw(name), name=name)
    if not isinstance(value, str):
        raise ValueError(f"配置项 {name} 必须是字符串")
    return value


def _env_optional_str(name: str) -> str | None:
    value = _env_str(name)
    return value or None


def _env_int(name: str) -> int:
    value = _decode_value(_raw(name), name=name)
    if isinstance(value, bool):
        raise ValueError(f"配置项 {name} 必须是整数")
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"[+-]?\d+", value.strip()):
        return int(value)
    raise ValueError(f"配置项 {name} 必须是整数")


def _env_float(name: str) -> float:
    value = _decode_value(_raw(name), name=name)
    if isinstance(value, bool):
        raise ValueError(f"配置项 {name} 必须是数字")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"配置项 {name} 必须是数字") from exc
    if not math.isfinite(parsed):
        raise ValueError(f"配置项 {name} 必须是有限数字")
    return parsed


def _env_bool(name: str) -> bool:
    value = _decode_value(_raw(name), name=name)
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"配置项 {name} 必须是布尔值")


def _env_optional_bool(name: str) -> bool | None:
    if not str(_raw(name)).strip():
        return None
    value = _decode_value(_raw(name), name=name)
    if isinstance(value, str) and not value.strip():
        return None
    return _env_bool(name)


def _env_str_list(name: str) -> list[str]:
    value = _decode_value(_raw(name), name=name)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"配置项 {name} 必须是 JSON 字符串数组")
    return value


# Web / session
SECRET_KEY = _env_optional_str("SECRET_KEY")
FLASK_DEBUG = _env_bool("FLASK_DEBUG")
SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE")
CONTENT_SECURITY_POLICY = _env_optional_str("CONTENT_SECURITY_POLICY")
CSRF_TRUSTED_ORIGINS = _env_str_list("CSRF_TRUSTED_ORIGINS")
LOG_LEVEL = _env_str("LOG_LEVEL")
LOG_TRUSTED_PROXY_CIDRS = _env_str_list("LOG_TRUSTED_PROXY_CIDRS")

# MySQL
MYSQL_HOST = _env_str("MYSQL_HOST")
MYSQL_PORT = _env_int("MYSQL_PORT")
MYSQL_DB = _env_str("MYSQL_DB")
MYSQL_USERNAME = _env_str("MYSQL_USERNAME")
MYSQL_PASSWORD = _env_str("MYSQL_PASSWORD")
MYSQL_CONNECT_TIMEOUT = _env_int("MYSQL_CONNECT_TIMEOUT")
MYSQL_POOL_MIN_SIZE = _env_int("MYSQL_POOL_MIN_SIZE")
MYSQL_POOL_MAX_SIZE = _env_int("MYSQL_POOL_MAX_SIZE")
MYSQL_POOL_WAIT_TIMEOUT = _env_int("MYSQL_POOL_WAIT_TIMEOUT")
MYSQL_POOL_RECYCLE_SECONDS = _env_int("MYSQL_POOL_RECYCLE_SECONDS")

AI_CODE_MARKS_IMAGE_ANALYSIS_TIMEOUT = _env_int(
    "AI_CODE_MARKS_IMAGE_ANALYSIS_TIMEOUT"
)

# Redis / snapshots
REDIS_HOST = _env_str("REDIS_HOST")
REDIS_PORT = _env_int("REDIS_PORT")
REDIS_DB = _env_int("REDIS_DB")
REDIS_SOCKET_TIMEOUT_SECONDS = _env_float("REDIS_SOCKET_TIMEOUT_SECONDS")
REDIS_CONNECT_TIMEOUT_SECONDS = _env_float("REDIS_CONNECT_TIMEOUT_SECONDS")
REDIS_BLOCKING_SOCKET_TIMEOUT_SECONDS = _env_float(
    "REDIS_BLOCKING_SOCKET_TIMEOUT_SECONDS"
)
SUBMISSION_SNAPSHOT_TTL_SECONDS = _env_int("SUBMISSION_SNAPSHOT_TTL_SECONDS")
EVALUATE_SUBMISSION_LOCK_TTL_SECONDS = _env_int(
    "EVALUATE_SUBMISSION_LOCK_TTL_SECONDS"
)

# Repository storage and index
REPOSITORY_STORAGE_ROOT = _env_str("REPOSITORY_STORAGE_ROOT")
REPOSITORY_MAX_FILE_BYTES = _env_int("REPOSITORY_MAX_FILE_BYTES")
REPOSITORY_MAX_TOTAL_BYTES = _env_int("REPOSITORY_MAX_TOTAL_BYTES")
REPOSITORY_MAX_ENTRIES = _env_int("REPOSITORY_MAX_ENTRIES")
REPOSITORY_MAX_DEPTH = _env_int("REPOSITORY_MAX_DEPTH")
REPOSITORY_MAX_PATH_BYTES = _env_int("REPOSITORY_MAX_PATH_BYTES")
REPOSITORY_UPLOAD_SESSION_TTL_SECONDS = _env_int(
    "REPOSITORY_UPLOAD_SESSION_TTL_SECONDS"
)
REPOSITORY_EMBEDDING_DIM = _env_int("REPOSITORY_EMBEDDING_DIM")
REPOSITORY_STRUCTURED_TIMEOUT = _env_int("REPOSITORY_STRUCTURED_TIMEOUT")
REPOSITORY_STRUCTURED_MAX_INPUT_CHARS = _env_int(
    "REPOSITORY_STRUCTURED_MAX_INPUT_CHARS"
)
REPOSITORY_EMBEDDING_TIMEOUT = _env_int("REPOSITORY_EMBEDDING_TIMEOUT")
REPOSITORY_EMBEDDING_BATCH_SIZE = _env_int("REPOSITORY_EMBEDDING_BATCH_SIZE")
REPOSITORY_VECTOR_BACKEND = _env_str("REPOSITORY_VECTOR_BACKEND")
REPOSITORY_FAISS_INDEX_ROOT = _env_str("REPOSITORY_FAISS_INDEX_ROOT")

# OCR / agent solver
LATEX_OCR_MAX_IMAGES_PER_REQUEST = _env_int("LATEX_OCR_MAX_IMAGES_PER_REQUEST")
LATEX_OCR_STREAM_EMIT_INTERVAL = _env_float("LATEX_OCR_STREAM_EMIT_INTERVAL")
LATEX_OCR_STREAM_EMIT_MIN_DELTA = _env_int("LATEX_OCR_STREAM_EMIT_MIN_DELTA")
AGENT_MAX_ROUNDS = _env_int("AGENT_MAX_ROUNDS")
AGENT_SUBMIT_LIMIT = _env_int("AGENT_SUBMIT_LIMIT")
AGENT_MEMORY_ENABLED = _env_bool("AGENT_MEMORY_ENABLED")
AGENT_CONTEXT_MAX_CHARS = _env_int("AGENT_CONTEXT_MAX_CHARS")
AGENT_CONTEXT_KEEP_ROUNDS = _env_int("AGENT_CONTEXT_KEEP_ROUNDS")
AGENT_MEMORY_MAX_PATTERNS = _env_int("AGENT_MEMORY_MAX_PATTERNS")
AGENT_MEMORY_MAX_NOTES = _env_int("AGENT_MEMORY_MAX_NOTES")
AGENT_MEMORY_MAX_DO_NOT_REPEAT = _env_int("AGENT_MEMORY_MAX_DO_NOT_REPEAT")
AGENT_REPOSITORY_KNN_TOP_K = _env_int("AGENT_REPOSITORY_KNN_TOP_K")
AGENT_REPOSITORY_KNN_SCORE_THRESHOLD = _env_float(
    "AGENT_REPOSITORY_KNN_SCORE_THRESHOLD"
)
AGENT_CONTEXT_SUMMARY_TIMEOUT = _env_int("AGENT_CONTEXT_SUMMARY_TIMEOUT")
AGENT_CONTEXT_SUMMARY_INPUT_MAX_CHARS = _env_int(
    "AGENT_CONTEXT_SUMMARY_INPUT_MAX_CHARS"
)
AGENT_CONTEXT_SUMMARY_OUTPUT_MAX_CHARS = _env_int(
    "AGENT_CONTEXT_SUMMARY_OUTPUT_MAX_CHARS"
)

# WebSearch MCP runtime limit; connection settings live in MySQL.
MODELSCOPE_WEB_SEARCH_TIMEOUT_SECONDS = _env_int(
    "MODELSCOPE_WEB_SEARCH_TIMEOUT_SECONDS"
)

# Agent-as-Judge / ordinary judge containers
AGENT_JUDGE_DOCKER_IMAGE = _env_str("AGENT_JUDGE_DOCKER_IMAGE")
AGENT_JUDGE_WORKSPACE_ROOT = _env_str("AGENT_JUDGE_WORKSPACE_ROOT")
AGENT_JUDGE_CONCURRENCY = _env_int("AGENT_JUDGE_CONCURRENCY")
AGENT_JUDGE_DEFAULT_TIMEOUT = _env_int("AGENT_JUDGE_DEFAULT_TIMEOUT")
AGENT_JUDGE_MEM_LIMIT = _env_str("AGENT_JUDGE_MEM_LIMIT")
AGENT_JUDGE_CPU_LIMIT = _env_str("AGENT_JUDGE_CPU_LIMIT")
AGENT_JUDGE_PIDS_LIMIT = _env_str("AGENT_JUDGE_PIDS_LIMIT")
AGENT_JUDGE_RESULT_POLL_INTERVAL = _env_float("AGENT_JUDGE_RESULT_POLL_INTERVAL")
AGENT_JUDGE_PROGRESS_TTL = _env_int("AGENT_JUDGE_PROGRESS_TTL")
JUDGER_DOCKER_IMAGE = _env_str("JUDGER_DOCKER_IMAGE")
JUDGER_DOCKER_MEM_LIMIT = _env_str("JUDGER_DOCKER_MEM_LIMIT")
JUDGER_DOCKER_CPU_LIMIT = _env_str("JUDGER_DOCKER_CPU_LIMIT")
JUDGER_DOCKER_PIDS_LIMIT = _env_str("JUDGER_DOCKER_PIDS_LIMIT")
JUDGER_DOCKER_NETWORK = _env_str("JUDGER_DOCKER_NETWORK")
JUDGER_DOCKER_RUNNER_UID = _env_int("JUDGER_DOCKER_RUNNER_UID")
JUDGER_DOCKER_RUNNER_GID = _env_int("JUDGER_DOCKER_RUNNER_GID")
JUDGER_DOCKER_CASE_TMPFS_BYTES = _env_int("JUDGER_DOCKER_CASE_TMPFS_BYTES")
JUDGER_DOCKER_EXPORT_TMPFS_BYTES = _env_int("JUDGER_DOCKER_EXPORT_TMPFS_BYTES")
JUDGER_CASE_INPUT_MAX_BYTES = _env_int("JUDGER_CASE_INPUT_MAX_BYTES")
JUDGER_STDOUT_MAX_BYTES = _env_int("JUDGER_STDOUT_MAX_BYTES")
JUDGER_STDERR_MAX_BYTES = _env_int("JUDGER_STDERR_MAX_BYTES")

# Judge paths and advanced runtime controls
OJ_ROOT_PATH = _env_optional_str("OJ_ROOT_PATH") or ""
JUDGER_RUN_ROOT = _env_optional_str("JUDGER_RUN_ROOT") or ""
JUDGER_TIMEOUT_KILL_AFTER_SEC = _env_float("JUDGER_TIMEOUT_KILL_AFTER_SEC")
JUDGER_OCTAVE_PLOT_WARMUP = _env_bool("JUDGER_OCTAVE_PLOT_WARMUP")
JUDGER_TARGET_ARCH = _env_str("JUDGER_TARGET_ARCH")
JUDGER_NUMERIC_BACKEND = _env_str("JUDGER_NUMERIC_BACKEND")
JUDGER_ENABLE_MKL = _env_optional_bool("JUDGER_ENABLE_MKL")

# Agent-as-Judge advanced limits
AGENT_JUDGE_TRACE_SYNC_INTERVAL_SECONDS = _env_float(
    "AGENT_JUDGE_TRACE_SYNC_INTERVAL_SECONDS"
)
AGENT_JUDGE_QUEUE_RETRY_SECONDS = _env_int("AGENT_JUDGE_QUEUE_RETRY_SECONDS")
AGENT_JUDGE_MAX_QUEUE_RETRIES = _env_int("AGENT_JUDGE_MAX_QUEUE_RETRIES")
AGENT_JUDGE_SLOT_TTL_BUFFER = _env_int("AGENT_JUDGE_SLOT_TTL_BUFFER")
AGENT_JUDGE_PACKAGE_MAX_MEMBERS = _env_int("AGENT_JUDGE_PACKAGE_MAX_MEMBERS")
AGENT_JUDGE_PACKAGE_MAX_FILE_BYTES = _env_int(
    "AGENT_JUDGE_PACKAGE_MAX_FILE_BYTES"
)
AGENT_JUDGE_PACKAGE_MAX_TOTAL_BYTES = _env_int(
    "AGENT_JUDGE_PACKAGE_MAX_TOTAL_BYTES"
)
AGENT_JUDGE_PACKAGE_MAX_COMPRESSION_RATIO = _env_float(
    "AGENT_JUDGE_PACKAGE_MAX_COMPRESSION_RATIO"
)
AGENT_JUDGE_HELLO_TIMEOUT_SECONDS = _env_float(
    "AGENT_JUDGE_HELLO_TIMEOUT_SECONDS"
)
AGENT_JUDGE_HELLO_RETRY_SLEEP_SECONDS = _env_float(
    "AGENT_JUDGE_HELLO_RETRY_SLEEP_SECONDS"
)
AGENT_JUDGE_PAUSED_PROBE_INTERVAL_SECONDS = _env_int(
    "AGENT_JUDGE_PAUSED_PROBE_INTERVAL_SECONDS"
)
AGENT_JUDGE_OPENCODE_HELLO_TIMEOUT_SECONDS = _env_float(
    "AGENT_JUDGE_OPENCODE_HELLO_TIMEOUT_SECONDS"
)

# Upload limits
TESTDATA_ZIP_MAX_MEMBERS = _env_int("TESTDATA_ZIP_MAX_MEMBERS")
TESTDATA_ZIP_MAX_FILE_BYTES = _env_int("TESTDATA_ZIP_MAX_FILE_BYTES")
TESTDATA_ZIP_MAX_TOTAL_BYTES = _env_int("TESTDATA_ZIP_MAX_TOTAL_BYTES")
TESTDATA_ZIP_MAX_COMPRESSION_RATIO = _env_float(
    "TESTDATA_ZIP_MAX_COMPRESSION_RATIO"
)
TESTDATA_TEXT_MAX_TOTAL_BYTES = _env_int("TESTDATA_TEXT_MAX_TOTAL_BYTES")

# Ranking batch operations
RANKING_BATCH_LSREMOTE_TIMEOUT = _env_int("RANKING_BATCH_LSREMOTE_TIMEOUT")
RANKING_BATCH_CLONE_TIMEOUT = _env_int("RANKING_BATCH_CLONE_TIMEOUT")
RANKING_BATCH_PROBE_CONCURRENCY = _env_int("RANKING_BATCH_PROBE_CONCURRENCY")
RANKING_BATCH_PROBE_MAX_USERS = _env_int("RANKING_BATCH_PROBE_MAX_USERS")
RANKING_BATCH_CLONE_ZIP_MAX_BYTES = _env_int("RANKING_BATCH_CLONE_ZIP_MAX_BYTES")
RANKING_BATCH_JOB_TTL = _env_int("RANKING_BATCH_JOB_TTL")
RANKING_BATCH_PULL_RETRY = _env_int("RANKING_BATCH_PULL_RETRY")
RANKING_BATCH_CREATE_RETRY = _env_int("RANKING_BATCH_CREATE_RETRY")
RANKING_BATCH_ITEM_SLEEP_SECONDS = _env_float("RANKING_BATCH_ITEM_SLEEP_SECONDS")
RANKING_BULK_REJUDGE_JOB_TTL = _env_int("RANKING_BULK_REJUDGE_JOB_TTL")
RANKING_BULK_REJUDGE_ITEM_SLEEP_SECONDS = _env_float(
    "RANKING_BULK_REJUDGE_ITEM_SLEEP_SECONDS"
)

# Reverse judge
REVERSE_JUDGE_PROGRESS_TTL = _env_int("REVERSE_JUDGE_PROGRESS_TTL")
REVERSE_JUDGE_WORKSPACE_ROOT = _env_str("REVERSE_JUDGE_WORKSPACE_ROOT")
REVERSE_JUDGE_SCRIPT_TIMEOUT = _env_int("REVERSE_JUDGE_SCRIPT_TIMEOUT")
REVERSE_JUDGE_TRACE_SYNC_INTERVAL = _env_float("REVERSE_JUDGE_TRACE_SYNC_INTERVAL")
REVERSE_JUDGE_STREAM_TIMEOUT_BUFFER_SECONDS = _env_int(
    "REVERSE_JUDGE_STREAM_TIMEOUT_BUFFER_SECONDS"
)
REVERSE_QUALITY_GATE_TIMEOUT_SECONDS = _env_int(
    "REVERSE_QUALITY_GATE_TIMEOUT_SECONDS"
)
REVERSE_QUALITY_GATE_MAX_PROMPT_CHARS = _env_int(
    "REVERSE_QUALITY_GATE_MAX_PROMPT_CHARS"
)
REVERSE_QUALITY_GATE_RESULT_MAX_BYTES = _env_int(
    "REVERSE_QUALITY_GATE_RESULT_MAX_BYTES"
)
REVERSE_PACKAGE_MAX_MEMBERS = _env_int("REVERSE_PACKAGE_MAX_MEMBERS")
REVERSE_PACKAGE_MAX_FILE_BYTES = _env_int("REVERSE_PACKAGE_MAX_FILE_BYTES")
REVERSE_PACKAGE_MAX_TOTAL_BYTES = _env_int("REVERSE_PACKAGE_MAX_TOTAL_BYTES")
REVERSE_PACKAGE_MAX_COMPRESSION_RATIO = _env_float(
    "REVERSE_PACKAGE_MAX_COMPRESSION_RATIO"
)
REVERSE_ANSWER_MAX_FILES = _env_int("REVERSE_ANSWER_MAX_FILES")
REVERSE_ANSWER_MAX_FILE_BYTES = _env_int("REVERSE_ANSWER_MAX_FILE_BYTES")
REVERSE_ANSWER_MAX_TOTAL_BYTES = _env_int("REVERSE_ANSWER_MAX_TOTAL_BYTES")
REVERSE_ENDPOINT_PROXY_MAX_REQUEST_BYTES = _env_int(
    "REVERSE_ENDPOINT_PROXY_MAX_REQUEST_BYTES"
)
REVERSE_ENDPOINT_PROXY_MAX_CONNECTIONS = _env_int(
    "REVERSE_ENDPOINT_PROXY_MAX_CONNECTIONS"
)
REVERSE_ENDPOINT_PROXY_CLIENT_TIMEOUT_SECONDS = _env_int(
    "REVERSE_ENDPOINT_PROXY_CLIENT_TIMEOUT_SECONDS"
)
REVERSE_ENDPOINT_PROXY_TIMEOUT_SECONDS = _env_int(
    "REVERSE_ENDPOINT_PROXY_TIMEOUT_SECONDS"
)
REVERSE_ENDPOINT_PROXY_BIND_HOST = _env_str("REVERSE_ENDPOINT_PROXY_BIND_HOST")
REVERSE_ENDPOINT_PROXY_CONTAINER_HOST = _env_str(
    "REVERSE_ENDPOINT_PROXY_CONTAINER_HOST"
)
REVERSE_TRACE_RETENTION_SECONDS = _env_int("REVERSE_TRACE_RETENTION_SECONDS")
REVERSE_TRACE_MAX_ATTEMPTS = _env_int("REVERSE_TRACE_MAX_ATTEMPTS")
REVERSE_TRACE_MIN_DELETE_AGE_SECONDS = _env_int(
    "REVERSE_TRACE_MIN_DELETE_AGE_SECONDS"
)
