#!/bin/sh
set -eu

workspace="${1:-/sandbox}"
compiled_dir="/tmp/numoj-lean"

mkdir -p "$compiled_dir"

mathlib_path="$(cat /opt/numoj-lean-path)"
export LEAN_PATH="$compiled_dir:$workspace:$mathlib_path"

# Lean 的 import 读取 .olean；先把完整学生文件编译到临时目录，再检查平台 bridge。
lean -o "$compiled_dir/Submission.olean" "$workspace/Submission.lean"
lean "$workspace/Solution.lean"
