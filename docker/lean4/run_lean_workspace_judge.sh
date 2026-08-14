#!/bin/sh
set -eu

workspace="${1:-/sandbox}"
target_module="${2:?target module is required}"
target_decl="${3:?target declaration is required}"
entry_module="${4:?entry module is required}"
entry_decl="${5:?entry declaration is required}"
permitted_axioms="${6:-}"
shift 6

student_output="/tmp/numoj-student-olean"
mkdir -p "$student_output"
mathlib_path="$(cat /opt/numoj-lean-path)"
export LEAN_PATH="$workspace/trusted-olean:$mathlib_path:$student_output"

library_path="$workspace/trusted-olean:$mathlib_path"
for relative_path in "$@"; do
  module_path="${relative_path%.lean}"
  saved_ifs="$IFS"
  IFS=:
  for library_root in $library_path; do
    if [ -e "$library_root/$module_path.olean" ]; then
      printf '%s\n' "__NUMOJ_WRITABLE_MODULE_CONFLICT__: $relative_path" >&2
      exit 1
    fi
  done
  IFS="$saved_ifs"
done

for relative_path in "$@"; do
  module_path="${relative_path%.lean}"
  output_path="$student_output/$module_path.olean"
  mkdir -p "$(dirname "$output_path")"
  lean -o "$output_path" "$workspace/student-src/$relative_path"
done

printf '%s\n' '__NUMOJ_VERIFIER_PROCESS_BEGIN__'
exec /usr/local/bin/numoj-lean-verifier \
  "$target_module" "$target_decl" "$entry_module" "$entry_decl" \
  "$permitted_axioms"
