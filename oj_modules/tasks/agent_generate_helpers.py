#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import shutil
import subprocess
import time
import zipfile

from oj_modules.tasks.agent_shared import *
from oj_modules.testdata_services import TestdataValidationError, import_testdata_zip

def _truncate_block_text(value, limit=12000):
    text = str(value or "")
    safe_limit = _clamp_int(limit, 12000, min_value=200, max_value=200000)
    if len(text) <= safe_limit:
        return text
    keep = safe_limit // 2
    return text[:keep] + "\n...<truncated>...\n" + text[-keep:]


def _resolve_workspace_path(workspace_dir, relative_path="", allow_workspace_root=False):
    if not workspace_dir:
        raise RuntimeError("workspace 未初始化。")
    root = os.path.abspath(str(workspace_dir))
    rel = str(relative_path or "").replace("\\", "/").strip()
    if not rel:
        if allow_workspace_root:
            return root
        raise RuntimeError("path 不能为空。")
    rel = rel.lstrip("/")
    norm_rel = os.path.normpath(rel)
    abs_path = os.path.abspath(os.path.join(root, norm_rel))
    if abs_path != root and not abs_path.startswith(root + os.sep):
        raise RuntimeError("path 不能越界到工作目录之外。")
    if abs_path == root and not allow_workspace_root:
        raise RuntimeError("path 不能指向工作目录根路径。")
    return abs_path


def _tool_data_agent_create_file(workspace_dir, path, content, overwrite=True):
    abs_path = _resolve_workspace_path(workspace_dir, path)
    parent = os.path.dirname(abs_path)
    os.makedirs(parent, exist_ok=True)
    if os.path.exists(abs_path) and not bool(overwrite):
        raise RuntimeError("目标文件已存在，且 overwrite=false。")
    text = str(content or "")
    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(text)
    return {
        "path": os.path.relpath(abs_path, workspace_dir),
        "bytes": len(text.encode("utf-8")),
    }


def _tool_data_agent_edit_file(
    workspace_dir,
    path,
    new_content=None,
    find_text=None,
    replace_text=None,
    replace_all=True,
):
    abs_path = _resolve_workspace_path(workspace_dir, path)
    if not os.path.isfile(abs_path):
        raise RuntimeError("目标文件不存在。")
    with open(abs_path, "r", encoding="utf-8") as f:
        original = f.read()

    if new_content is not None:
        updated = str(new_content)
        replace_count = 1
    else:
        src = str(find_text or "")
        if not src:
            raise RuntimeError("缺少 find_text 或 new_content。")
        dst = str(replace_text or "")
        if bool(replace_all):
            updated = original.replace(src, dst)
            replace_count = original.count(src)
        else:
            updated = original.replace(src, dst, 1)
            replace_count = 1 if src in original else 0
        if replace_count <= 0:
            raise RuntimeError("未找到待替换文本。")

    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(updated)
    return {
        "path": os.path.relpath(abs_path, workspace_dir),
        "replaced": int(replace_count),
        "bytes": len(updated.encode("utf-8")),
    }


def _tool_data_agent_read_file(workspace_dir, path, max_chars=12000):
    abs_path = _resolve_workspace_path(workspace_dir, path)
    if not os.path.isfile(abs_path):
        raise RuntimeError("目标文件不存在。")
    with open(abs_path, "r", encoding="utf-8") as f:
        content = f.read()
    return {
        "path": os.path.relpath(abs_path, workspace_dir),
        "content": _truncate_block_text(content, limit=max_chars),
        "truncated": len(content) > _clamp_int(max_chars, 12000, min_value=200, max_value=200000),
    }


def _tool_data_agent_list_files(workspace_dir, path="", recursive=True, max_entries=500):
    base_abs = _resolve_workspace_path(workspace_dir, path, allow_workspace_root=True)
    safe_max = _clamp_int(max_entries, 500, min_value=1, max_value=3000)
    rows = []
    if bool(recursive):
        for root, dirnames, filenames in os.walk(base_abs):
            dirnames.sort()
            filenames.sort()
            rel_root = os.path.relpath(root, workspace_dir)
            for dirname in dirnames:
                rel_path = os.path.normpath(os.path.join(rel_root, dirname))
                rows.append({"path": rel_path, "is_dir": True, "size": 0})
                if len(rows) >= safe_max:
                    return {"entries": rows, "truncated": True}
            for filename in filenames:
                abs_file = os.path.join(root, filename)
                rel_path = os.path.normpath(os.path.join(rel_root, filename))
                try:
                    size = os.path.getsize(abs_file)
                except Exception:
                    size = 0
                rows.append({"path": rel_path, "is_dir": False, "size": int(size)})
                if len(rows) >= safe_max:
                    return {"entries": rows, "truncated": True}
    else:
        for name in sorted(os.listdir(base_abs)):
            abs_item = os.path.join(base_abs, name)
            rel_path = os.path.relpath(abs_item, workspace_dir)
            is_dir = os.path.isdir(abs_item)
            try:
                size = 0 if is_dir else os.path.getsize(abs_item)
            except Exception:
                size = 0
            rows.append({"path": rel_path, "is_dir": bool(is_dir), "size": int(size)})
            if len(rows) >= safe_max:
                return {"entries": rows, "truncated": True}
    return {"entries": rows, "truncated": False}


def _tool_data_agent_run_command(workspace_dir, command, timeout_seconds=60):
    cmd = str(command or "").strip()
    if not cmd:
        raise RuntimeError("command 不能为空。")
    timeout_val = _clamp_int(timeout_seconds, 60, min_value=1, max_value=900)
    try:
        proc = subprocess.run(
            ["bash", "-lc", cmd],
            cwd=workspace_dir,
            capture_output=True,
            text=True,
            timeout=timeout_val,
            check=False,
        )
        return {
            "success": proc.returncode == 0,
            "exit_code": int(proc.returncode),
            "stdout": _truncate_block_text(proc.stdout, limit=16000),
            "stderr": _truncate_block_text(proc.stderr, limit=16000),
            "timeout": False,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "success": False,
            "exit_code": None,
            "stdout": _truncate_block_text(e.stdout or "", limit=16000),
            "stderr": _truncate_block_text(e.stderr or "", limit=16000),
            "timeout": True,
            "message": f"命令执行超时（{timeout_val}s）",
        }


def _tool_data_agent_merge_interactor_with_user_code(interactor_code, user_code):
    interactor = str(interactor_code or "")
    user = str(user_code or "")
    marker = "%%user_code_here"
    marker_count = interactor.count(marker)
    if marker_count != 1:
        raise RuntimeError(f"交互程序中 {marker} 的数量应为 1，当前为 {marker_count}。")
    return interactor.replace(marker, user)


def _tool_data_agent_zip_testdata(workspace_dir, test_point_count, data_dir="", zip_name="testdata.zip"):
    count = _clamp_int(test_point_count, 10, min_value=1, max_value=5000)
    base_dir = _resolve_workspace_path(workspace_dir, data_dir, allow_workspace_root=True)
    name = str(zip_name or "testdata.zip").strip()
    if not name.lower().endswith(".zip"):
        name = f"{name}.zip"
    zip_abs = _resolve_workspace_path(workspace_dir, name)

    missing_files = []
    for idx in range(1, count + 1):
        in_file = os.path.join(base_dir, f"{idx}.in")
        out_file = os.path.join(base_dir, f"{idx}.out")
        if not os.path.isfile(in_file):
            missing_files.append(f"{idx}.in")
        if not os.path.isfile(out_file):
            missing_files.append(f"{idx}.out")
    if missing_files:
        raise RuntimeError(f"测试数据文件缺失：{', '.join(missing_files[:20])}")

    os.makedirs(os.path.dirname(zip_abs), exist_ok=True)
    with zipfile.ZipFile(zip_abs, "w", zipfile.ZIP_DEFLATED) as zf:
        for idx in range(1, count + 1):
            in_file = os.path.join(base_dir, f"{idx}.in")
            out_file = os.path.join(base_dir, f"{idx}.out")
            zf.write(in_file, arcname=f"{idx}.in")
            zf.write(out_file, arcname=f"{idx}.out")

    return {
        "zip_path": os.path.relpath(zip_abs, workspace_dir),
        "zip_abs_path": zip_abs,
        "count": count,
    }


def _tool_data_agent_upload_testdata(problem_id, zip_abs_path, workspace_dir):
    if not os.path.isfile(zip_abs_path):
        raise RuntimeError("zip 文件不存在。")
    extract_dir = os.path.join(
        workspace_dir,
        f".extract_upload_{int(time.time() * 1000)}",
    )
    os.makedirs(extract_dir, exist_ok=True)
    try:
        result = import_testdata_zip(problem_id=problem_id, zip_path=zip_abs_path, extract_dir=extract_dir)
        return {
            "uploaded_count": int(result.get("count") or 0),
        }
    except zipfile.BadZipFile as e:
        raise RuntimeError(f"无效 zip 文件：{e}") from e
    except TestdataValidationError as e:
        raise RuntimeError(str(e)) from e
    finally:
        try:
            shutil.rmtree(extract_dir)
        except Exception:
            pass


def _parse_numeric_tokens(lines):
    tokens = []
    for line_no, line in enumerate(lines, start=1):
        for token in re.split(r"[,\s]+", str(line or "").strip()):
            if not token:
                continue
            try:
                value = float(token)
            except Exception:
                return [], False, False
            tokens.append({
                "line_no": line_no,
                "token": token,
                "value": value,
            })
    return tokens, True, len(tokens) > 0


def _extract_nearby_lines(lines, center_line_no, total_lines=3):
    if not lines:
        return []
    safe_total = _clamp_int(total_lines, 3, min_value=1, max_value=21)
    center = _clamp_int(center_line_no, 1, min_value=1, max_value=len(lines))
    radius = safe_total // 2
    start = max(1, center - radius)
    end = min(len(lines), start + safe_total - 1)
    start = max(1, end - safe_total + 1)
    return [{"line_no": idx, "content": lines[idx - 1]} for idx in range(start, end + 1)]


def _tool_data_agent_diff_text(workspace_dir, left_file, right_file, context_lines=3):
    safe_ctx = _clamp_int(context_lines, 3, min_value=0, max_value=60)
    left_abs = _resolve_workspace_path(workspace_dir, left_file)
    right_abs = _resolve_workspace_path(workspace_dir, right_file)
    if not os.path.isfile(left_abs):
        raise RuntimeError(f"左侧文件不存在：{left_file}")
    if not os.path.isfile(right_abs):
        raise RuntimeError(f"右侧文件不存在：{right_file}")

    with open(left_abs, "r", encoding="utf-8", errors="replace") as f:
        left_text = f.read()
    with open(right_abs, "r", encoding="utf-8", errors="replace") as f:
        right_text = f.read()

    left_lines = left_text.splitlines()
    right_lines = right_text.splitlines()
    left_tokens, left_is_numeric, left_has_token = _parse_numeric_tokens(left_lines)
    right_tokens, right_is_numeric, right_has_token = _parse_numeric_tokens(right_lines)
    is_numeric_file = bool(left_is_numeric and right_is_numeric and (left_has_token or right_has_token))

    if is_numeric_file:
        left_count = len(left_tokens)
        right_count = len(right_tokens)
        paired_count = min(left_count, right_count)
        max_abs_error = None
        max_error_index = None
        max_left_line_no = None
        max_right_line_no = None

        for idx in range(paired_count):
            delta = abs(left_tokens[idx]["value"] - right_tokens[idx]["value"])
            if max_abs_error is None or delta > max_abs_error:
                max_abs_error = float(delta)
                max_error_index = idx + 1
                max_left_line_no = int(left_tokens[idx]["line_no"])
                max_right_line_no = int(right_tokens[idx]["line_no"])

        if max_abs_error is None:
            max_abs_error = 0.0
            max_left_line_no = 1 if left_lines else 0
            max_right_line_no = 1 if right_lines else 0

        return {
            "mode": "numeric",
            "is_numeric": True,
            "same": (left_count == right_count and max_abs_error == 0.0),
            "left_file": os.path.relpath(left_abs, workspace_dir),
            "right_file": os.path.relpath(right_abs, workspace_dir),
            "left_token_count": left_count,
            "right_token_count": right_count,
            "paired_token_count": paired_count,
            "token_count_mismatch": left_count != right_count,
            "max_abs_error": max_abs_error,
            "max_error_token_index": max_error_index,
            "max_error_left_line": max_left_line_no,
            "max_error_right_line": max_right_line_no,
            "left_nearby_lines": _extract_nearby_lines(left_lines, max_left_line_no, total_lines=3) if max_left_line_no else [],
            "right_nearby_lines": _extract_nearby_lines(right_lines, max_right_line_no, total_lines=3) if max_right_line_no else [],
        }

    proc = subprocess.run(
        ["diff", "-u", f"-U{safe_ctx}", "--", left_abs, right_abs],
        cwd=workspace_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError((proc.stderr or proc.stdout or "diff 执行失败").strip())
    diff_output = proc.stdout or ""
    return {
        "mode": "text",
        "is_numeric": False,
        "same": proc.returncode == 0,
        "diff": _truncate_block_text(diff_output, limit=20000),
        "exit_code": int(proc.returncode),
        "left_file": os.path.relpath(left_abs, workspace_dir),
        "right_file": os.path.relpath(right_abs, workspace_dir),
    }


def _build_data_generation_tools():
    return [
        {
            "type": "function",
            "function": {
                "name": "get_context",
                "description": "读取本题数据生成任务上下文信息。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "max_problem_chars": {"type": "integer", "description": "题面最大返回字符数，默认 12000"},
                        "max_interactor_chars": {"type": "integer", "description": "交互程序最大返回字符数，默认 12000"},
                        "max_standard_chars": {"type": "integer", "description": "标准程序最大返回字符数，默认 12000"},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "create_file",
                "description": "创建文件（代码文件或文本文件）。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "工作目录内相对路径"},
                        "content": {"type": "string", "description": "完整文件内容"},
                        "overwrite": {"type": "boolean", "description": "文件存在时是否覆盖，默认 true"},
                    },
                    "required": ["path", "content"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "edit_file",
                "description": "编辑已存在文件。可整文件替换，或按 find_text 替换。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "工作目录内相对路径"},
                        "new_content": {"type": "string", "description": "若提供则直接整文件替换"},
                        "find_text": {"type": "string", "description": "待替换文本"},
                        "replace_text": {"type": "string", "description": "替换后的文本"},
                        "replace_all": {"type": "boolean", "description": "是否替换全部，默认 true"},
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "读取工作目录内文件内容。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "相对路径"},
                        "max_chars": {"type": "integer", "description": "最大字符数，默认 12000"},
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "list_files",
                "description": "列出工作目录中的文件。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "相对路径，默认根目录"},
                        "recursive": {"type": "boolean", "description": "是否递归，默认 true"},
                        "max_entries": {"type": "integer", "description": "最大条数，默认 500"},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "run_command",
                "description": "在 Debian 工作目录执行命令（用于编译/运行/打包）。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "bash 命令"},
                        "timeout_seconds": {"type": "integer", "description": "超时秒数，默认 60"},
                    },
                    "required": ["command"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "diff_text",
                "description": "对比两个文件。若均为数值文件则返回最大浮点误差及附近三行；否则返回系统 diff 结果。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "left_file": {"type": "string", "description": "左侧文件相对路径"},
                        "right_file": {"type": "string", "description": "右侧文件相对路径"},
                        "context_lines": {"type": "integer", "description": "上下文行数，默认 3"},
                    },
                    "required": ["left_file", "right_file"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "merge_interactor_with_user_code",
                "description": "将标准程序插入交互程序中的 %%user_code_here，占位符必须且仅能出现一次。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "interactor_code": {"type": "string", "description": "交互程序代码，不传则使用题目交互程序"},
                        "user_code": {"type": "string", "description": "标准程序代码，不传则使用初始标准程序"},
                        "output_path": {"type": "string", "description": "可选。若提供则把合并结果写入该路径"},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "zip_testdata",
                "description": "将 1.in/1.out ... n.in/n.out 打包为 zip。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "data_dir": {"type": "string", "description": "测试数据目录（相对路径），默认根目录"},
                        "zip_name": {"type": "string", "description": "zip 文件名，默认 testdata.zip"},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "upload_testdata",
                "description": "调用系统上传数据逻辑，把 zip 导入当前题目的测试数据。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "zip_path": {"type": "string", "description": "zip 相对路径；不传则使用最近一次 zip_testdata 产物"},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "submit_solution",
                "description": "提交标准程序到系统评测并等待结果。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "可选。提交时使用该代码"},
                        "timeout_seconds": {"type": "integer", "description": "等待评测超时，默认 300 秒"},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "submit_standard_solution",
                "description": "提交标准程序到系统评测并等待结果。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "可选。提交时使用该代码"},
                        "timeout_seconds": {"type": "integer", "description": "等待评测超时，默认 300 秒"},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_submission_result",
                "description": "查询某次提交的评测结果并等待至终态或超时。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "submission_id": {"type": "integer", "description": "提交 ID"},
                        "timeout_seconds": {"type": "integer", "description": "等待评测超时，默认 300 秒"},
                    },
                    "required": ["submission_id"],
                },
            },
        },
    ]


def _build_data_generation_initial_prompt(problem, interactor_code, standard_code, test_point_count, data_requirement=""):
    lang = (problem.get("lang") or "cpp").lower()
    problem_content = str(problem.get("content") or "").strip()
    extra_requirement = str(data_requirement or "").strip()
    if extra_requirement:
        problem_content += f"\n\n【数据生成要求】\n{extra_requirement}"
    interactor = str(interactor_code or "").strip()
    standard = str(standard_code or "").strip()
    n = _clamp_int(test_point_count, 10, min_value=1, max_value=5000)
    lang_extra_prompt = ""
    if lang in ("python", "py"):
        lang_extra_prompt = "系统提供了 python3 以及 numpy、pandas 等一切必要的工具，你不必自己安装依赖。\n\n"
    elif lang in ("matlab", "octave"):
        lang_extra_prompt = "系统没有 MATLAB 环境，但提供了 octave 环境，请用 octave 来代替执行 MATLAB 代码。\n\n"
    return (
        "你是一个生成数据的 Agent，你需要为在线评测系统生成数据。现在题目已经出好，只是还没有配置数据。你首先需要获取：\n"
        "1. 题目要求\n"
        "2. 本题的交互程序\n"
        "3. 本题标准程序如下\n"
        "4. 本题需要配置多少个测试点。\n"
        "交互程序会包含且仅包含一个 %%user_code_here，这个字符串需要替换成标准程序，合并成一个文件后才能编译。\n"
        "你的工作环境是 Debian 12，你有一个工作目录，你可以在这个文件夹里编译运行程序、创建文件，可以创建任何类型的文件，例如代码文件、文本文件 等等。\n"
        "你的工作流程如下：\n"
        "0. 获取你所需的信息。\n"
        f"1. 写一个 python 程序，用于生成本题的测试数据 1.in/1.out ... {n}.in/{n}.out，也可以只生成 in，然后通过编译运行标准程序来获得 out 文件。\n"
        "2. 生成好以后，写一个 bash 脚本，用于编译运行本题的标准程序，确保标准程序在读取到 in 时，能输出正确的 out 文件。\n"
        "3. 若标准程序输出错误，请重复上面两步，直到标准程序输出正确为止。\n"
        "4. 确认无误后，将所有 in/out 文件其打包为 zip，并调用工具上传。\n"
        "5. 上传数据后，将标准程序提交系统测试，看是否通过所有测试点。\n"
        "6. 若标准程序没有通过测试，请从 1 开始重复上述步骤，直到标准程序能通过所有测试点为止。\n\n"
        f"你最多只能调用 {_AGENT_SUBMIT_LIMIT} 次 submit_solution，"
        f"若 {_AGENT_SUBMIT_LIMIT} 次还没成功，你会被强制终止。\n\n"
        f"{lang_extra_prompt}"
        "现在，请你调用 get_context 获取题目要求、交互程序、标准程序以及其它详细说明。"
    )



__all__ = [name for name in globals().keys() if not name.startswith("__")]
