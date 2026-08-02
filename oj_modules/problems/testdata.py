#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import shutil

import config as _cfg
from oj_modules.infrastructure.mysql import get_db_connection
from oj_modules.shared.archive import (
    ArchiveExtractionError,
    ZipExtractionPolicy,
    extract_zip,
)


class TestdataValidationError(Exception):
    pass


TESTDATA_ZIP_MAX_MEMBERS = max(
    2, int(getattr(_cfg, 'TESTDATA_ZIP_MAX_MEMBERS', 4096)),
)
TESTDATA_ZIP_MAX_FILE_BYTES = max(
    1024 * 1024,
    int(getattr(_cfg, 'TESTDATA_ZIP_MAX_FILE_BYTES', 128 * 1024 * 1024)),
)
TESTDATA_ZIP_MAX_TOTAL_BYTES = max(
    TESTDATA_ZIP_MAX_FILE_BYTES,
    int(getattr(_cfg, 'TESTDATA_ZIP_MAX_TOTAL_BYTES', 256 * 1024 * 1024)),
)
TESTDATA_ZIP_MAX_COMPRESSION_RATIO = max(
    10.0,
    float(getattr(_cfg, 'TESTDATA_ZIP_MAX_COMPRESSION_RATIO', 500.0)),
)
TESTDATA_TEXT_MAX_TOTAL_BYTES = max(
    1,
    int(getattr(_cfg, 'TESTDATA_TEXT_MAX_TOTAL_BYTES', 64 * 1024 * 1024)),
)


def _numeric_name_sort_key(filename):
    stem = os.path.splitext(str(filename or ""))[0]
    try:
        return (0, int(stem))
    except Exception:
        return (1, stem)


def load_testdata_from_extracted_dir(extract_dir, *, max_total_text_bytes=None):
    if not os.path.isdir(extract_dir):
        raise TestdataValidationError("解压目录不存在。")

    text_size_limit = (
        TESTDATA_TEXT_MAX_TOTAL_BYTES
        if max_total_text_bytes is None
        else max(1, int(max_total_text_bytes))
    )

    in_files = sorted(
        [f for f in os.listdir(extract_dir) if str(f).endswith('.in')],
        key=_numeric_name_sort_key,
    )
    out_files = sorted(
        [f for f in os.listdir(extract_dir) if str(f).endswith('.out')],
        key=_numeric_name_sort_key,
    )

    if len(in_files) != len(out_files):
        raise TestdataValidationError("输入文件和输出文件数量不匹配。")
    if not in_files:
        raise TestdataValidationError("ZIP 中未找到任何 .in/.out 测试数据文件。")

    paired_paths = []
    total_text_bytes = 0
    # 先按磁盘上的实际文件大小完成全量预检，再读取任何文本。这样超限包不会在
    # Python 字符串、strip() 与 JSON 序列化阶段产生数倍内存放大。
    for in_file, out_file in zip(in_files, out_files):
        base_in = os.path.splitext(in_file)[0]
        base_out = os.path.splitext(out_file)[0]
        if base_in != base_out:
            raise TestdataValidationError(f"输入文件 {in_file} 与输出文件 {out_file} 名称不匹配。")

        in_path = os.path.join(extract_dir, in_file)
        out_path = os.path.join(extract_dir, out_file)
        try:
            total_text_bytes += os.path.getsize(in_path)
            total_text_bytes += os.path.getsize(out_path)
        except OSError as exc:
            raise TestdataValidationError(f"无法读取测试数据文件大小：{exc}") from exc
        if total_text_bytes > text_size_limit:
            raise TestdataValidationError(
                "测试数据 .in/.out 文本总大小超过限制"
                f"（上限 {text_size_limit} 字节）。"
            )
        paired_paths.append((in_path, out_path))

    testdata = []
    for in_path, out_path in paired_paths:
        try:
            with open(in_path, 'r', encoding='utf-8') as f_in:
                input_data = f_in.read().strip()
            with open(out_path, 'r', encoding='utf-8') as f_out:
                output_data = f_out.read().strip()
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


def import_testdata_zip(problem_id, zip_path, extract_dir):
    # 调用方为每次导入提供专用临时目录；先清理崩溃遗留，避免旧 .in/.out 混入新包。
    shutil.rmtree(extract_dir, ignore_errors=True)
    policy = ZipExtractionPolicy(
        max_members=TESTDATA_ZIP_MAX_MEMBERS,
        max_file_bytes=TESTDATA_ZIP_MAX_FILE_BYTES,
        max_total_bytes=TESTDATA_ZIP_MAX_TOTAL_BYTES,
        max_compression_ratio=TESTDATA_ZIP_MAX_COMPRESSION_RATIO,
        require_non_empty=True,
        cleanup_on_error=True,
    )
    try:
        extract_zip(zip_path, extract_dir, policy=policy)
    except ArchiveExtractionError as exc:
        messages = {
            'empty_archive': 'ZIP 压缩包为空。',
            'too_many_members': 'ZIP 文件数量超过限制。',
            'file_too_large': 'ZIP 中单个测试数据文件超过大小限制。',
            'total_too_large': 'ZIP 解压后总大小超过限制。',
            'compression_ratio': 'ZIP 包含异常压缩比文件。',
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
        update_problem_testdata(problem_id, testdata)
    except Exception:
        shutil.rmtree(extract_dir, ignore_errors=True)
        raise
    return {
        "count": len(testdata),
        "testdata": testdata,
    }
