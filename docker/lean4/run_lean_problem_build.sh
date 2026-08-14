#!/bin/sh
set -eu

source_root="${1:?source root is required}"
output_root="${2:?output root is required}"
shift 2

mkdir -p "$output_root"
mathlib_path="$(cat /opt/numoj-lean-path)"
export LEAN_PATH="$output_root:$mathlib_path"

for relative_path in "$@"; do
  module_path="${relative_path%.lean}"
  output_path="$output_root/$module_path.olean"
  mkdir -p "$(dirname "$output_path")"
  lean -o "$output_path" "$source_root/$relative_path"
done
