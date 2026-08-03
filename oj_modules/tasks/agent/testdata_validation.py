#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""造数据 Agent 的标准程序 staging 验证。

本模块只调用 Docker 判题核心，不创建 submission，也不读写数据库。调用方先把
候选测试数据解析为内存对象，再在真正发布前使用标准程序逐点验证。
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping

from oj_modules.judging import core
from oj_modules.judging.programming import (
    build_programming_source,
    compare_float_strings,
)


_MEMORY_LIMIT_BYTES = 512 * 1024 * 1024
_MAX_TEST_POINTS = 5000
_RESULT_TEXT_LIMIT = 500

__all__ = ["validate_staged_testdata"]


def _failure(status, message, *, test_points=None, score=0):
    return {
        "success": False,
        "status": str(status),
        "score": int(score),
        "test_points": list(test_points or []),
        "message": str(message),
    }


def _text(value, *, limit=_RESULT_TEXT_LIMIT):
    text = value if isinstance(value, str) else str(value or "")
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _normalize_testdata(testdata):
    value = testdata
    if isinstance(value, (str, bytes, bytearray)):
        try:
            value = json.loads(value)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
            return None, "测试数据不是合法的 JSON"
    if not isinstance(value, list):
        return None, "测试数据必须是测试点数组"
    if not value:
        return None, "测试数据不能为空"
    if len(value) > _MAX_TEST_POINTS:
        return None, f"测试点数量不能超过 {_MAX_TEST_POINTS}"

    normalized = []
    for index, item in enumerate(value, start=1):
        if not isinstance(item, Mapping):
            return None, f"第 {index} 个测试点格式无效"
        normalized.append({
            "input": item.get("input", "")
            if isinstance(item.get("input", ""), str)
            else str(item.get("input", "") or ""),
            "output": item.get("output", "")
            if isinstance(item.get("output", ""), str)
            else str(item.get("output", "") or ""),
        })
    return normalized, ""


def _staging_sid(task_id):
    task_digest = hashlib.sha256(
        str(task_id or "unknown").encode("utf-8", errors="replace")
    ).hexdigest()[:16]
    return f"agent-testdata-validation-{task_digest}-{uuid.uuid4().hex[:16]}"


def _time_limit_ns(problem):
    raw_value = problem.get("time_limit_ms") or 2000
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        raise ValueError("题目时间限制无效") from None
    if value <= 0:
        raise ValueError("题目时间限制必须为正整数")
    return value * 1_000_000


def _build_test_point(index, test_case, run_result):
    if not isinstance(run_result, Mapping):
        return {
            "test_index": index,
            "status": "Error",
            "stdout": "",
            "stderr": "判题核心未返回该测试点的有效结果",
            "time": 0,
        }

    status = str(run_result.get("status") or "Error").strip() or "Error"
    files = run_result.get("files")
    if not isinstance(files, Mapping):
        files = {}
    raw_actual_output = files.get("stdout", "")
    if not isinstance(raw_actual_output, str):
        raw_actual_output = str(raw_actual_output or "")
    normalized_actual_output = raw_actual_output.strip()
    actual_output = _text(normalized_actual_output)
    stderr = _text(files.get("stderr", ""))
    if status == "Accepted" and not compare_float_strings(
        normalized_actual_output,
        str(test_case.get("output", "")).strip(),
    ):
        status = "Wrong Answer"

    try:
        elapsed_ms = int(round(int(run_result.get("time") or 0) / 1_000_000))
    except (TypeError, ValueError):
        elapsed_ms = 0
    return {
        "test_index": index,
        "status": status,
        "stdout": actual_output,
        "stderr": stderr,
        "time": elapsed_ms,
    }


def validate_staged_testdata(problem, standard_code, testdata, *, task_id):
    """用标准程序验证尚未发布的测试数据，且不创建提交或修改题目。

    语义性失败（评分模式、源码、测试数据、编译和逐点运行结果）统一返回结构化
    字典。判题基础设施异常会在清理本次 sid 的产物后以 ``RuntimeError`` 抛出。
    """

    if not isinstance(problem, Mapping):
        return _failure("Error", "题目信息无效")
    try:
        problem_type = int(problem.get("type") or 1)
        grading_mode = int(problem.get("programming_grading_mode") or 1)
    except (TypeError, ValueError):
        return _failure("Error", "题目评分配置无效")
    if problem_type != 1:
        return _failure("Unsupported", "仅支持编程题的测试数据验证")
    if grading_mode != 1:
        return _failure("Unsupported", "仅支持标准测试点评分模式")

    submitted_code = str(standard_code or "")
    if not submitted_code.strip():
        return _failure("Error", "标准程序不能为空")
    test_cases, testdata_error = _normalize_testdata(testdata)
    if testdata_error:
        return _failure("Error", testdata_error)

    language = str(problem.get("lang") or "matlab").strip().lower()
    test_code = str(problem.get("test_code") or "")
    try:
        final_code = build_programming_source(
            language,
            submitted_code,
            test_code,
        )
        time_limit_ns = _time_limit_ns(problem)
    except ValueError as exc:
        return _failure("Error", str(exc))

    sid = _staging_sid(task_id)
    payload = {
        "code": final_code,
        "submittedCode": submitted_code,
        "checkerCode": test_code,
        "test_cases": test_cases,
        "forbidden": str(problem.get("forbidden_func") or ""),
        "sid": sid,
        "timeLimit": time_limit_ns,
        "memoryLimit": _MEMORY_LIMIT_BYTES,
        "user_files": [],
        "outputImageFilename": "output.png",
    }
    try:
        try:
            batch_result = core.batch_evaluate(language, payload)
        except Exception as exc:
            raise RuntimeError(f"标准程序 staging 判题失败：{exc}") from exc

        if not isinstance(batch_result, Mapping):
            raise RuntimeError("标准程序 staging 判题未返回有效结果")
        compile_result = batch_result.get("compile_result")
        if not isinstance(compile_result, Mapping):
            raise RuntimeError("标准程序 staging 判题缺少编译结果")

        compile_status = str(compile_result.get("status") or "error").strip().lower()
        if compile_status != "success":
            status = "Forbidden" if compile_status == "forbidden" else "Compile Error"
            diagnostic = _text(compile_result.get("stderr", ""))
            message = f"标准程序{status}"
            if diagnostic:
                message += f"：{diagnostic}"
            return _failure(status, message)

        raw_results = batch_result.get("test_results")
        if not isinstance(raw_results, list):
            raise RuntimeError("标准程序 staging 判题缺少测试点结果")

        test_points = []
        for offset, test_case in enumerate(test_cases):
            run_result = raw_results[offset] if offset < len(raw_results) else None
            test_points.append(
                _build_test_point(offset + 1, test_case, run_result)
            )
        if len(raw_results) != len(test_cases):
            # 多出的结果同样说明判题协议失配；缺少的结果已被逐点标记为 Error。
            if len(raw_results) > len(test_cases):
                test_points.append({
                    "test_index": len(test_cases) + 1,
                    "status": "Error",
                    "stdout": "",
                    "stderr": "判题核心返回了多余的测试点结果",
                    "time": 0,
                })

        score = sum(
            1 for item in test_points if item.get("status") == "Accepted"
        )
        if score == len(test_cases) and len(test_points) == len(test_cases):
            return {
                "success": True,
                "status": "Accepted",
                "score": score,
                "test_points": test_points,
                "message": f"标准程序通过全部 {len(test_cases)} 个测试点",
            }

        failed = next(
            item for item in test_points if item.get("status") != "Accepted"
        )
        failed_count = len(test_points) - score
        return _failure(
            "Unaccepted",
            (
                f"标准程序有 {failed_count} 个测试点未通过；"
                f"首个失败点为第 {failed['test_index']} 点（{failed['status']}）"
            ),
            test_points=test_points,
            score=score,
        )
    finally:
        try:
            core.cleanup_run_artifacts(
                sid,
                keep_images=False,
                keep_sources=False,
            )
        except Exception:
            # 清理函数本身已是 best-effort；不得让清理错误覆盖真实判题结果。
            pass
