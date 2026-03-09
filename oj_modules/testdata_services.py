#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import zipfile

from oj_modules.db_services import get_db_connection


class TestdataValidationError(Exception):
    pass


def _numeric_name_sort_key(filename):
    stem = os.path.splitext(str(filename or ""))[0]
    try:
        return (0, int(stem))
    except Exception:
        return (1, stem)


def load_testdata_from_extracted_dir(extract_dir):
    if not os.path.isdir(extract_dir):
        raise TestdataValidationError("解压目录不存在。")

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

    testdata = []
    for in_file, out_file in zip(in_files, out_files):
        base_in = os.path.splitext(in_file)[0]
        base_out = os.path.splitext(out_file)[0]
        if base_in != base_out:
            raise TestdataValidationError(f"输入文件 {in_file} 与输出文件 {out_file} 名称不匹配。")

        in_path = os.path.join(extract_dir, in_file)
        out_path = os.path.join(extract_dir, out_file)
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
            cursor.execute("UPDATE problems SET testdata=%s WHERE id=%s", (testdata_json, problem_id))
            cursor.execute("UPDATE problems SET max_score=%s WHERE id=%s", (len(testdata), problem_id))
        conn.commit()
    finally:
        conn.close()


def import_testdata_zip(problem_id, zip_path, extract_dir):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)
    testdata = load_testdata_from_extracted_dir(extract_dir)
    update_problem_testdata(problem_id, testdata)
    return {
        "count": len(testdata),
        "testdata": testdata,
    }
