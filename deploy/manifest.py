#!/usr/bin/env python3
"""从 Git 的 NUL 分隔路径生成部署清单。

``deploy/rsync-excludes.txt`` 是唯一排除规则来源；本工具只接受仓库当前
使用的、可明确解释的 rsync 规则子集，遇到未知语法会失败关闭。
"""

from __future__ import annotations

import argparse
import fnmatch
from pathlib import Path, PurePosixPath


class ExcludeRules:
    def __init__(self, patterns: tuple[str, ...]):
        self.patterns = patterns

    @classmethod
    def load(cls, path: Path) -> "ExcludeRules":
        patterns: list[str] = []
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            pattern = raw_line.strip()
            if not pattern or pattern.startswith("#"):
                continue
            if any(token in pattern for token in ("[", "]", "?", "**")):
                raise ValueError(f"unsupported deploy exclude pattern: {pattern!r}")
            if "*" in pattern and pattern != "*.pyc":
                raise ValueError(f"unsupported deploy exclude pattern: {pattern!r}")
            patterns.append(pattern)
        return cls(tuple(patterns))

    def matches(self, relative: str) -> bool:
        path = _safe_path(relative)
        components = path.parts
        for pattern in self.patterns:
            if pattern.startswith("/"):
                anchored = pattern[1:]
                if anchored.endswith("/"):
                    prefix = anchored.rstrip("/")
                    if relative == prefix or relative.startswith(prefix + "/"):
                        return True
                elif relative == anchored:
                    return True
            elif "/" in pattern:
                raise ValueError(f"unanchored path exclude is ambiguous: {pattern!r}")
            elif any(fnmatch.fnmatch(component, pattern) for component in components):
                return True
        return False


def _safe_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not value
        or "\n" in value
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"unsafe deploy path: {value!r}")
    return path


def build_manifest(
    paths: list[str], rules: ExcludeRules
) -> tuple[list[str], bytes]:
    included = sorted({_safe_path(path).as_posix() for path in paths if not rules.matches(path)})
    manifest = "".join(f"{path}\n" for path in included)
    nul_paths = b"".join(path.encode("utf-8") + b"\0" for path in included)
    return manifest.splitlines(), nul_paths


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--excludes", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--nul-output", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    raw_paths = args.input.read_bytes().split(b"\0")
    if raw_paths and raw_paths[-1] == b"":
        raw_paths.pop()
    paths = [value.decode("utf-8", errors="strict") for value in raw_paths]
    included, nul_paths = build_manifest(paths, ExcludeRules.load(args.excludes))
    args.manifest.write_text(
        "".join(f"{path}\n" for path in included), encoding="utf-8"
    )
    args.nul_output.write_bytes(nul_paths)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
