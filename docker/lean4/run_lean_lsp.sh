#!/bin/sh
set -eu

workspace="${1:-/workspace}"

mathlib_path="$(cat /opt/numoj-lean-path)"
export LEAN_PATH="$mathlib_path:$workspace"
exec lean --server
