# -*- coding: utf-8 -*-
"""本地真实 AI E2E 的唯一 DeepSeek 配置入口。"""

from __future__ import annotations

from pathlib import Path

import config


ROOT = Path(__file__).resolve().parents[2]
DEEPSEEK_MODEL = "deepseek-v4-flash"
DEEPSEEK_OPENAI_BASE_URL = "https://api.deepseek.com/v1"
DEEPSEEK_ANTHROPIC_BASE_URL = "https://api.deepseek.com/anthropic"


def read_deepseek_api_key() -> str:
    """只从本地 .env 读取 live E2E 密钥，不接受进程环境回退。"""

    values = config._read_env_file(ROOT / ".env", required=False)
    raw = values.get("DEEPSEEK_API_KEY")
    if raw is None:
        raise RuntimeError("本地 .env 缺少 DEEPSEEK_API_KEY")
    value = config._decode_value(raw, name="DEEPSEEK_API_KEY")
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError("本地 .env 中的 DEEPSEEK_API_KEY 为空或格式无效")
    return value.strip()


__all__ = [
    "DEEPSEEK_ANTHROPIC_BASE_URL",
    "DEEPSEEK_MODEL",
    "DEEPSEEK_OPENAI_BASE_URL",
    "read_deepseek_api_key",
]
