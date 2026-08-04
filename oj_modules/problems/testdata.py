#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
import shutil
import zipfile

from oj_modules.infrastructure.mysql import get_db_connection
from oj_modules.shared.archive import (
    ArchiveExtractionError,
    ZipExtractionPolicy,
    extract_zip,
)


class TestdataValidationError(Exception):
    pass


_TESTDATA_FILENAME = re.compile(r"^([1-9][0-9]*)\.(in|out)$")


def load_testdata_from_extracted_dir(extract_dir):
    if not os.path.isdir(extract_dir):
        raise TestdataValidationError("解压目录不存在。")

    pairs = {}
    for entry in os.scandir(extract_dir):
        if not entry.is_file(follow_symlinks=False):
            raise TestdataValidationError(
                "ZIP 根目录只能包含 1.in/1.out 至 n.in/n.out 文件。"
            )
        matched = _TESTDATA_FILENAME.fullmatch(entry.name)
        if not matched:
            raise TestdataValidationError(
                "ZIP 根目录只能包含 1.in/1.out 至 n.in/n.out 文件。"
            )
        index = int(matched.group(1))
        pairs.setdefault(index, {})[matched.group(2)] = entry.path

    if not pairs:
        raise TestdataValidationError("ZIP 中未找到任何 .in/.out 测试数据文件。")
    expected_indexes = set(range(1, max(pairs) + 1))
    if set(pairs) != expected_indexes or any(
        set(files) != {"in", "out"} for files in pairs.values()
    ):
        raise TestdataValidationError(
            "测试数据必须从 1.in/1.out 开始连续编号且成对出现。"
        )

    testdata = []
    for index in sorted(pairs):
        try:
            with open(pairs[index]["in"], 'r', encoding='utf-8') as f_in:
                input_data = f_in.read()
            with open(pairs[index]["out"], 'r', encoding='utf-8') as f_out:
                output_data = f_out.read()
        except UnicodeDecodeError as e:
            raise TestdataValidationError(f"文件编码错误（需 UTF-8）：{e}") from e

        testdata.append({
            'input': input_data,
            'output': output_data,
        })
    return testdata


def update_problem_testdata(problem_id, testdata):
    if not isinstance(testdata, list) or not testdata:
        raise TestdataValidationError("测试数据为空。")

    testdata_json = json.dumps(testdata, ensure_ascii=False)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE problems SET testdata=%s, max_score=%s WHERE id=%s",
                (testdata_json, len(testdata), problem_id),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_problem_testdata_state(problem_id):
    """读取可用于乐观并发控制的测试数据原始状态。"""

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT testdata, max_score FROM problems WHERE id=%s",
                (problem_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "testdata": row.get("testdata"),
                "max_score": row.get("max_score"),
            }
    finally:
        conn.close()


def parse_testdata_zip(zip_path, extract_dir):
    """安全解压并解析测试数据 ZIP，但不修改题目或其他数据库状态。

    ``extract_dir`` 必须是调用方为本次操作独占的临时目录。函数会先删除该目录
    中可能残留的文件；解析失败时也会清理已解压的部分内容。返回值可以先交给
    判题器验证，验证通过后再由 :func:`publish_staged_testdata` 原子发布。
    """

    # 调用方为每次导入提供专用临时目录；先清理崩溃遗留，避免旧 .in/.out 混入新包。
    shutil.rmtree(extract_dir, ignore_errors=True)
    policy = ZipExtractionPolicy(
        max_members=None,
        max_file_bytes=None,
        max_total_bytes=None,
        max_compression_ratio=None,
        cleanup_on_error=True,
    )
    try:
        extract_zip(zip_path, extract_dir, policy=policy)
    except (zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise TestdataValidationError("文件不是有效的 ZIP 压缩包。") from exc
    except ArchiveExtractionError as exc:
        messages = {
            'absolute_path': 'ZIP 包含绝对路径。',
            'path_traversal': 'ZIP 包含目录穿越路径。',
            'outside_destination': 'ZIP 包含越界路径。',
            'symlink': 'ZIP 不能包含符号链接。',
            'encrypted_member': 'ZIP 不能包含加密文件。',
            'duplicate_target': 'ZIP 包含重复路径。',
            'target_conflict': 'ZIP 包含文件与目录冲突路径。',
            'size_mismatch': 'ZIP 文件大小校验失败。',
        }
        raise TestdataValidationError(messages.get(exc.reason, 'ZIP 解压失败。')) from exc
    try:
        testdata = load_testdata_from_extracted_dir(extract_dir)
    except Exception:
        shutil.rmtree(extract_dir, ignore_errors=True)
        raise
    return {
        "count": len(testdata),
        "testdata": testdata,
    }


def publish_staged_testdata(problem_id, *, before_state, testdata):
    """仅在题目仍处于 ``before_state`` 时原子发布已验证的测试数据。

    读取旧值、比较和更新都在同一数据库事务及行锁内完成，因此失败只会返回
    ``False``，不会先暴露新数据再尝试回滚。``before_state`` 应直接来自
    :func:`get_problem_testdata_state`，保留数据库中的原始可空值。
    """

    if not isinstance(before_state, dict) or not {
        "testdata", "max_score",
    }.issubset(before_state):
        raise ValueError("before_state 缺少测试数据原始状态")
    if not isinstance(testdata, list) or not testdata:
        raise TestdataValidationError("测试数据为空。")

    replacement_testdata = json.dumps(testdata, ensure_ascii=False)
    replacement_max_score = len(testdata)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT testdata, max_score FROM problems WHERE id=%s FOR UPDATE",
                (problem_id,),
            )
            current = cursor.fetchone()
            if (
                not current
                or current.get("testdata") != before_state.get("testdata")
                or current.get("max_score") != before_state.get("max_score")
            ):
                conn.rollback()
                return False
            cursor.execute(
                "UPDATE problems SET testdata=%s, max_score=%s WHERE id=%s",
                (replacement_testdata, replacement_max_score, problem_id),
            )
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def import_testdata_zip(problem_id, zip_path, extract_dir):
    """兼容管理员直接上传：安全解析后立即更新题目测试数据。"""

    result = parse_testdata_zip(zip_path, extract_dir)
    update_problem_testdata(problem_id, result["testdata"])
    return result
