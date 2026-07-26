#!/usr/bin/env python3
"""Run inside the judge image and copy its compiler header search safely."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys


SEARCH_MANIFEST = "compiler-search.json"
MAX_EXPORT_FILES = 200_000
MAX_EXPORT_BYTES = 2 * 1024 * 1024 * 1024


class ExportError(RuntimeError):
    pass


def _compiler_search(command: str, language: str, standard: str) -> list[Path]:
    result = subprocess.run(
        [command, "-E", "-x", language, f"-std={standard}", "-v", "-"],
        input="",
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise ExportError(f"{command} include search probe failed")
    inside = False
    paths: list[Path] = []
    for raw_line in result.stderr.splitlines():
        line = raw_line.strip()
        if line == "#include <...> search starts here:":
            inside = True
            continue
        if inside and line == "End of search list.":
            break
        if not inside:
            continue
        candidate = Path(line.split(" (framework directory)", 1)[0])
        if candidate.is_absolute() and candidate.is_dir():
            resolved = candidate.resolve(strict=True)
            if resolved not in paths:
                paths.append(resolved)
    if not paths:
        raise ExportError(f"{command} returned no include search roots")
    return paths


@dataclass
class _Budget:
    files: int = 0
    bytes: int = 0

    def add(self, size: int) -> None:
        self.files += 1
        self.bytes += size
        if self.files > MAX_EXPORT_FILES or self.bytes > MAX_EXPORT_BYTES:
            raise ExportError("judge header export exceeds safety limit")


def _copy_regular_file(source: Path, destination: Path, budget: _Budget) -> None:
    source_stat = source.stat()
    if not stat.S_ISREG(source_stat.st_mode):
        raise ExportError(f"unsupported header entry: {source}")
    budget.add(source_stat.st_size)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with source.open("rb") as source_stream, destination.open("xb") as output:
        shutil.copyfileobj(source_stream, output, length=1024 * 1024)
    destination.chmod(0o600)


def _copy_tree(
    source: Path,
    destination: Path,
    *,
    allowed_roots: tuple[Path, ...],
    budget: _Budget,
    active_directories: set[tuple[int, int]],
) -> None:
    resolved_source = source.resolve(strict=True)
    if not any(
        resolved_source == allowed_root
        or resolved_source.is_relative_to(allowed_root)
        for allowed_root in allowed_roots
    ):
        raise ExportError(f"header symlink escapes export roots: {source}")
    source_stat = resolved_source.stat()
    if stat.S_ISREG(source_stat.st_mode):
        _copy_regular_file(resolved_source, destination, budget)
        return
    if not stat.S_ISDIR(source_stat.st_mode):
        raise ExportError(f"unsupported header entry: {source}")

    directory_key = (source_stat.st_dev, source_stat.st_ino)
    if directory_key in active_directories:
        raise ExportError(f"header symlink directory cycle: {source}")
    active_directories.add(directory_key)
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        with os.scandir(resolved_source) as entries:
            for entry in entries:
                if entry.name in {"", ".", ".."} or "/" in entry.name:
                    raise ExportError("invalid header entry name")
                _copy_tree(
                    Path(entry.path),
                    destination / entry.name,
                    allowed_roots=allowed_roots,
                    budget=budget,
                    active_directories=active_directories,
                )
    finally:
        active_directories.remove(directory_key)


def _minimal_copy_roots(
    compiler_paths: tuple[Path, ...],
) -> tuple[Path, ...]:
    roots: list[Path] = []
    for candidate in sorted(compiler_paths, key=lambda path: len(path.parts)):
        if any(
            candidate == root or candidate.is_relative_to(root)
            for root in roots
        ):
            continue
        roots.append(candidate)
    return tuple(roots)


def export_headers(output: Path) -> None:
    output = output.resolve(strict=True)
    c_paths = _compiler_search("gcc", "c", "c11")
    cpp_paths = _compiler_search("g++", "c++", "c++20")
    compiler_paths = tuple(dict.fromkeys((*c_paths, *cpp_paths)))
    budget = _Budget()

    for source_root in _minimal_copy_roots(compiler_paths):
        destination = output.joinpath(*source_root.relative_to("/").parts)
        _copy_tree(
            source_root,
            destination,
            allowed_roots=compiler_paths,
            budget=budget,
            active_directories=set(),
        )

    for source_raw, destination_raw, allowed_prefix in (
        ("/opt/mkl/include", "opt/mkl/include", "/opt/intel/oneapi/mkl"),
        ("/opt/library", "opt/library", "/opt/library"),
    ):
        source = Path(source_raw)
        resolved = source.resolve(strict=True)
        allowed = Path(allowed_prefix).resolve(strict=True)
        try:
            resolved.relative_to(allowed)
        except ValueError as exc:
            raise ExportError(
                f"official include root escaped expected image path: {source}"
            ) from exc
        _copy_tree(
            resolved,
            output / destination_raw,
            allowed_roots=(resolved,),
            budget=budget,
            active_directories=set(),
        )

    payload = {
        "schema_version": 1,
        "c": [path.as_posix() for path in c_paths],
        "cpp": [path.as_posix() for path in cpp_paths],
    }
    search_path = output / SEARCH_MANIFEST
    with search_path.open("x", encoding="utf-8") as stream:
        json.dump(payload, stream, sort_keys=True)
        stream.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        export_headers(args.output)
    except (ExportError, OSError, subprocess.SubprocessError) as exc:
        print(f"[editor-header-export] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
