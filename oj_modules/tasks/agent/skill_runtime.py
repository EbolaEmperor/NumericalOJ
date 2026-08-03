#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把仓库中的 NumOJ skill 安全投影到一次性 harness 工作区。"""

from __future__ import annotations

import ast
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile


_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_SKILLS_ROOT = _REPOSITORY_ROOT / "skills"
_ALLOWED_SOURCE_SKILLS = frozenset({"numoj-user", "numoj-admin"})
_ALLOWED_HARNESSES = frozenset({"claude_code", "codex", "opencode", "pi"})
_SKILL_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_FRONTMATTER_KEY_RE = re.compile(
    r"^([A-Za-z][A-Za-z0-9_-]*):(?:[ \t]*(.*?))?\r?\n?$"
)
_MAX_SKILL_FILE_BYTES = 2 * 1024 * 1024
_MAX_SKILL_TOTAL_BYTES = 8 * 1024 * 1024
_MAX_SKILL_FILES = 512
_MAX_SKILL_DEPTH = 16
_IGNORED_DIRECTORY_NAMES = frozenset({"__pycache__"})
_IGNORED_FILE_NAMES = frozenset({".DS_Store"})
_IGNORED_FILE_SUFFIXES = frozenset({".pyc", ".pyo"})

# 四个 CLI 对 Agent Skills 标准的可选字段支持并不相同。这里按镜像中
# 的 harness 格式分别列出可识别字段，未知字段不投影，避免某个
# harness 的私有字段被另一个 harness 误解释。
_CORE_FRONTMATTER_FIELDS = frozenset({"name", "description"})
_FRONTMATTER_FIELDS_BY_HARNESS = {
    "claude_code": _CORE_FRONTMATTER_FIELDS
    | frozenset(
        {
            "agent",
            "allowed-tools",
            "argument-hint",
            "arguments",
            "context",
            "disable-model-invocation",
            "disallowed-tools",
            "effort",
            "hooks",
            "model",
            "paths",
            "shell",
            "user-invocable",
            "when_to_use",
        }
    ),
    "codex": _CORE_FRONTMATTER_FIELDS
    | frozenset({"license", "allowed-tools", "metadata"}),
    "opencode": _CORE_FRONTMATTER_FIELDS
    | frozenset({"license", "compatibility", "metadata"}),
    "pi": _CORE_FRONTMATTER_FIELDS
    | frozenset(
        {
            "license",
            "compatibility",
            "metadata",
            "allowed-tools",
            "disable-model-invocation",
        }
    ),
}


def _normalize_harness(value):
    harness = str(value or "").strip().lower().replace("-", "_")
    if harness == "pi_agent":
        harness = "pi"
    if harness not in _ALLOWED_HARNESSES:
        raise ValueError("Agent skill harness 无效")
    return harness


def _normalize_source_skill(value):
    source_skill = str(value or "").strip()
    if source_skill not in _ALLOWED_SOURCE_SKILLS:
        raise ValueError("Agent source skill 无效")
    return source_skill


def _split_frontmatter(text):
    lines = str(text or "").splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        raise ValueError("SKILL.md 缺少 YAML frontmatter")
    closing_index = None
    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            closing_index = index
            break
    if closing_index is None:
        raise ValueError("SKILL.md 的 YAML frontmatter 未闭合")
    return lines[1:closing_index], "".join(lines[closing_index + 1 :])


def _frontmatter_blocks(lines):
    blocks = []
    seen = set()
    current_key = None
    current_lines = []

    def flush():
        nonlocal current_key, current_lines
        if current_key is not None:
            blocks.append((current_key, tuple(current_lines)))
        current_key = None
        current_lines = []

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            if current_key is not None:
                current_lines.append(line)
            continue
        if line[:1].isspace():
            if current_key is None:
                raise ValueError("SKILL.md frontmatter 包含孤立的缩进行")
            current_lines.append(line)
            continue
        match = _FRONTMATTER_KEY_RE.fullmatch(line)
        if not match:
            raise ValueError("SKILL.md frontmatter 只允许顶层 YAML 字段")
        flush()
        current_key = match.group(1)
        if current_key in seen:
            raise ValueError(f"SKILL.md frontmatter 字段重复：{current_key}")
        seen.add(current_key)
        current_lines = [line]
    flush()
    return blocks


def _scalar_value(block_lines):
    first_line = block_lines[0].rstrip("\r\n")
    raw = first_line.split(":", 1)[1].strip()
    if raw.startswith(("|", ">")):
        values = [line.strip() for line in block_lines[1:] if line.strip()]
        return ("\n" if raw.startswith("|") else " ").join(values).strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {"'", '"'}:
        try:
            value = ast.literal_eval(raw)
        except (SyntaxError, ValueError):
            raise ValueError("SKILL.md frontmatter 标量格式无效") from None
        return str(value).strip()
    if " #" in raw:
        raw = raw.split(" #", 1)[0].rstrip()
    return raw


def _render_skill(source_text, harness, expected_name):
    frontmatter_lines, body = _split_frontmatter(source_text)
    blocks = _frontmatter_blocks(frontmatter_lines)
    values = {key: _scalar_value(lines) for key, lines in blocks}
    name = values.get("name", "")
    description = values.get("description", "")
    if name != expected_name or not _SKILL_NAME_RE.fullmatch(name):
        raise ValueError("SKILL.md name 必须与 source skill 目录一致")
    if not description:
        raise ValueError("SKILL.md description 不能为空")
    if len(description) > 1024:
        raise ValueError("SKILL.md description 不能超过 1024 字符")

    allowed = _FRONTMATTER_FIELDS_BY_HARNESS[harness]
    rendered_blocks = []
    for key, lines in blocks:
        if key not in allowed:
            continue
        block = "".join(lines)
        if block and not block.endswith(("\n", "\r")):
            block += "\n"
        rendered_blocks.append(block)
    if "name" not in {key for key, _lines in blocks if key in allowed}:
        raise ValueError("所选 harness 无法识别 SKILL.md name")
    if "description" not in {key for key, _lines in blocks if key in allowed}:
        raise ValueError("所选 harness 无法识别 SKILL.md description")
    return "---\n" + "".join(rendered_blocks) + "---\n" + body


def _target_relative_path(harness, source_skill):
    if harness == "claude_code":
        return Path(".runtime/home/.claude/skills") / source_skill
    if harness == "codex":
        # Codex 按 Agent Skills 约定从 $HOME/.agents/skills 发现用户级 skill；
        # CODEX_HOME 只承载 CLI 配置与会话，不把 skill 绑到其私有目录。
        return Path(".runtime/home/.agents/skills") / source_skill
    if harness == "opencode":
        return Path(".runtime/opencode/config/opencode/skills") / source_skill
    return Path(".runtime/pi/skills") / source_skill


def _safe_target(workspace, relative_path):
    root = Path(workspace).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("Agent skill workspace 不存在")
    target = (root / relative_path).resolve()
    if target == root or root not in target.parents:
        raise ValueError("Agent skill 投影目录越界")
    return root, target


def _ignored_source_entry(path):
    return (
        path.name in _IGNORED_DIRECTORY_NAMES
        or path.name in _IGNORED_FILE_NAMES
        or path.suffix.lower() in _IGNORED_FILE_SUFFIXES
    )


def _copy_source_tree(source, destination, rendered_skill):
    file_count = 0
    total_bytes = 0
    for current_root, directory_names, file_names in os.walk(
        source, topdown=True, followlinks=False
    ):
        current = Path(current_root)
        relative_root = current.relative_to(source)
        if len(relative_root.parts) > _MAX_SKILL_DEPTH:
            raise ValueError("source skill 目录层级过深")

        kept_directories = []
        for name in sorted(directory_names):
            source_dir = current / name
            if _ignored_source_entry(source_dir):
                continue
            if source_dir.is_symlink() or not source_dir.is_dir():
                raise ValueError("source skill 不能包含符号链接或特殊目录")
            kept_directories.append(name)
            target_dir = destination / relative_root / name
            target_dir.mkdir(parents=True, exist_ok=False)
            target_dir.chmod(0o755)
        directory_names[:] = kept_directories

        for name in sorted(file_names):
            source_file = current / name
            if _ignored_source_entry(source_file):
                continue
            if relative_root == Path(".") and name == "SKILL.md":
                continue
            try:
                source_stat = source_file.lstat()
            except OSError as exc:
                raise ValueError("无法读取 source skill 文件") from exc
            if source_file.is_symlink() or not stat.S_ISREG(source_stat.st_mode):
                raise ValueError("source skill 只能包含普通文件")
            if source_stat.st_size > _MAX_SKILL_FILE_BYTES:
                raise ValueError("source skill 包含过大的单文件")
            file_count += 1
            total_bytes += int(source_stat.st_size)
            if file_count > _MAX_SKILL_FILES or total_bytes > _MAX_SKILL_TOTAL_BYTES:
                raise ValueError("source skill 文件数量或总大小超限")
            target_file = destination / relative_root / name
            shutil.copyfile(source_file, target_file, follow_symlinks=False)
            mode = stat.S_IMODE(source_stat.st_mode) & ~0o022
            target_file.chmod(mode or 0o444)

    skill_file = destination / "SKILL.md"
    skill_file.write_text(rendered_skill, encoding="utf-8")
    skill_file.chmod(0o444)


def materialize_skill(workspace, harness, source_skill):
    """实时读取并投影一个受信任的 NumOJ skill，返回任务内目标目录。"""

    harness = _normalize_harness(harness)
    source_skill = _normalize_source_skill(source_skill)
    source_candidate = _SKILLS_ROOT / source_skill
    if source_candidate.is_symlink():
        raise ValueError("source skill 目录不存在或不安全")
    source = source_candidate.resolve()
    skills_root = _SKILLS_ROOT.resolve()
    if source.parent != skills_root or not source.is_dir() or source.is_symlink():
        raise ValueError("source skill 目录不存在或不安全")
    source_skill_file = source / "SKILL.md"
    try:
        source_stat = source_skill_file.lstat()
    except OSError as exc:
        raise ValueError("source skill 缺少 SKILL.md") from exc
    if source_skill_file.is_symlink() or not stat.S_ISREG(source_stat.st_mode):
        raise ValueError("source skill 的 SKILL.md 必须是普通文件")
    if source_stat.st_size > _MAX_SKILL_FILE_BYTES:
        raise ValueError("source skill 的 SKILL.md 过大")
    source_text = source_skill_file.read_text(encoding="utf-8")
    rendered_skill = _render_skill(source_text, harness, source_skill)

    relative_target = _target_relative_path(harness, source_skill)
    _root, target = _safe_target(workspace, relative_target)
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{source_skill}-", dir=str(target.parent))
    )
    try:
        staging.chmod(0o700)
        _copy_source_tree(source, staging, rendered_skill)
        if target.exists() or target.is_symlink():
            if target.is_symlink() or not target.is_dir():
                raise ValueError("Agent skill 目标路径已被非目录占用")
            shutil.rmtree(target)
        os.replace(staging, target)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return target


__all__ = ["materialize_skill"]
