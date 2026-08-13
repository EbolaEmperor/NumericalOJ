#!/bin/sh
set -eu

workspace="${1:-/workspace}"

mathlib_path="$(cat /opt/numoj-lean-path)"
export LEAN_PATH="$workspace:$mathlib_path"
exec lean --server
