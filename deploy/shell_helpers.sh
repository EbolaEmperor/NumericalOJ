#!/usr/bin/env bash

# 本文件只定义无外部状态的部署原语，供 remote.sh 与纯单元测试共同使用。

numoj_is_safe_path() {
  local path="$1"
  [[ -n "$path" && "$path" != /* && "$path" != '.' \
    && "$path" != '..' && "$path" != ../* && "$path" != */../* && "$path" != */.. ]]
}

numoj_atomic_symlink() {
  local target="$1"
  local link="$2"
  local token="$3"
  local temporary="$link.tmp-$token"
  rm -f -- "$temporary" || return 1
  ln -s "$target" "$temporary" || return 1
  python3 - "$temporary" "$link" <<'PY'
import os
import sys

os.replace(sys.argv[1], sys.argv[2])
PY
}

numoj_require_free_bytes() {
  local path="$1"
  local required_bytes="$2"
  local label="$3"
  python3 - "$path" "$required_bytes" "$label" <<'PY'
import os
import sys

path, raw_required, label = sys.argv[1:]
try:
    required = int(raw_required)
except ValueError as exc:
    raise SystemExit(f"{label} 磁盘余量阈值不是整数：{raw_required}") from exc
if required < 0:
    raise SystemExit(f"{label} 磁盘余量阈值不能为负数：{required}")
try:
    filesystem = os.statvfs(path)
except OSError as exc:
    raise SystemExit(f"无法检查 {label} 所在文件系统 {path}：{exc}") from exc
available = filesystem.f_bavail * filesystem.f_frsize
print(f"{label} 可用空间：{available} bytes；最低要求：{required} bytes")
if available < required:
    raise SystemExit(f"{label} 磁盘余量不足，部署失败关闭")
PY
}
