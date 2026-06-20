#!/usr/bin/env python3
"""Create a MATLAB problem package skeleton with paired data files."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SUCCESS = "Today is crazy Thursday. Let's eat crazy fish!!!"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a MATLAB problem package skeleton."
    )
    parser.add_argument("output_dir", help="Directory to create")
    parser.add_argument(
        "--cases",
        type=int,
        default=5,
        help="Number of paired data files to create (default: 5)",
    )
    return parser.parse_args()


def fail(message: str) -> int:
    print(f"[ERROR] {message}", file=sys.stderr)
    return 1


def write_if_missing(path: Path, content: str) -> None:
    if path.exists():
        raise FileExistsError(f"{path} already exists")
    path.write_text(content, encoding="utf-8")


def main() -> int:
    args = parse_args()
    if args.cases <= 0:
        return fail("--cases must be positive")

    root = Path(args.output_dir).resolve()
    if root.exists() and any(root.iterdir()):
        return fail(f"output directory is not empty: {root}")

    root.mkdir(parents=True, exist_ok=True)
    data_dir = root / "data"
    data_dir.mkdir(exist_ok=True)

    problem_md = """# [Problem Title]

## 题目描述

[TODO: describe the MATLAB task, signatures, constraints, and target complexity.]
"""
    interactor_m = """1;  % Keep this file as a script for Octave.

function write_success()
    fileID = fopen('output.txt', 'w');
    fprintf(fileID, 'Today is crazy Thursday. Let''s eat crazy fish!!!');
    fclose(fileID);
end

%%user_code_here

inputData = importdata(\"input.txt\");
write_success();
"""
    template_m = """function varargout = solveTask(varargin)
    % TODO: define the actual solver API for contestants.
end
"""
    solution_m = """function varargout = solveTask(varargin)
    % TODO: replace with the full reference solution.
end
"""
    config_json = json.dumps(
        {"timeLimit": "2000ms", "forbidden": ""},
        indent=2,
        ensure_ascii=False,
    ) + "\n"

    try:
        write_if_missing(root / "problem.md", problem_md)
        write_if_missing(root / "interactor.m", interactor_m)
        write_if_missing(root / "template.m", template_m)
        write_if_missing(root / "solution.m", solution_m)
        write_if_missing(root / "config.json", config_json)
        for index in range(1, args.cases + 1):
            write_if_missing(data_dir / f"{index}.in", "")
            write_if_missing(data_dir / f"{index}.out", SUCCESS + "\n")
    except FileExistsError as exc:
        return fail(str(exc))

    print(f"[OK] Created MATLAB problem skeleton at {root}")
    print(f"[OK] Created {args.cases} paired data files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
