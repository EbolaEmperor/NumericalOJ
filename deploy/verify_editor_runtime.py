#!/usr/bin/env python3
"""Fail closed when production editor language runtimes are incomplete."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oj_modules.editor.clangd import verify_clangd_runtime  # noqa: E402
from oj_modules.editor.octave import (  # noqa: E402
    verify_octave_language_runtime,
)
from oj_modules.editor.python import (  # noqa: E402
    verify_python_language_runtime,
)


def main() -> int:
    try:
        verify_clangd_runtime(require_official_toolchain=True)
        basedpyright_version = verify_python_language_runtime()
        verify_octave_language_runtime()
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"[editor-runtime] {exc}", file=sys.stderr)
        return 1
    print(
        f"clangd semantic tokens ready; {basedpyright_version}; "
        "tree-sitter-matlab ready"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
