#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把线上生产 config.py 里的真实 AI 配置合并进 CI 的 config.py。

用法:
    python3 merge_prod_ai_config.py <prod_config.py> <ci_config.py>

只覆盖 AI 相关的键（DashScope / Qwen / MiMo / MATLAB 检测器等），其余键
（MySQL / Redis 指向 docker-compose 服务、Agent 限额等）保持 CI 原值不变。
密钥只在 CI 运行时存在于容器内，绝不写入仓库。

实现：把两个 config 作为模块分别加载，从 prod 取白名单键的值，追加写到 CI
config 末尾（后定义覆盖先定义）。成功 exit 0，任何异常 exit 1，让调用方回退。
"""
import importlib.util
import sys


# 仅注入这些 AI 相关键（线上有才覆盖；其余 CI 键保持不变）。
AI_KEYS = [
    "DASHSCOPE_APP_ID",
    "DASHSCOPE_API_KEY",
    "DASHSCOPE_BASE_URL",
    "QWEN_CODER_MODEL",
    "QWEN_TEXT_MODEL",
    "QWEN_OMNI_MODEL",
    "AI_TUTOR_MODEL",
    "MIMO_URL_OPENAI",
    "MIMO_URL_ANTHROPIC",
    "MIMO_API_KEY",
    "MIMO_MODEL",
    "MATLAB_AI_DETECT_API_KEY",
    "MATLAB_AI_DETECT_URL",
    "MATLAB_AI_DETECT_MODEL",
    "REPOSITORY_QWEN_EMBEDDING_MODEL",
    "REPOSITORY_EMBEDDING_PROVIDER",
]


def _load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    if len(sys.argv) != 3:
        print("usage: merge_prod_ai_config.py <prod_config.py> <ci_config.py>",
              file=sys.stderr)
        return 1
    prod_path, ci_path = sys.argv[1], sys.argv[2]

    try:
        prod = _load_module(prod_path, "prod_config")
    except Exception as e:
        print(f"[merge] 无法加载线上 config: {e}", file=sys.stderr)
        return 1

    injected = []
    lines = ["", "# ===== 运行时注入：线上真实 AI 配置（仅 CI 容器内，不入库）====="]
    for key in AI_KEYS:
        if hasattr(prod, key):
            val = getattr(prod, key)
            lines.append(f"{key} = {val!r}")
            injected.append(key)

    if not injected:
        print("[merge] 线上 config 未提供任何 AI 键，放弃注入", file=sys.stderr)
        return 1

    try:
        with open(ci_path, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except Exception as e:
        print(f"[merge] 写入 CI config 失败: {e}", file=sys.stderr)
        return 1

    # 不打印密钥本身，只报告注入了哪些键名。
    print(f"[merge] 已注入 {len(injected)} 个 AI 键: {', '.join(injected)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
