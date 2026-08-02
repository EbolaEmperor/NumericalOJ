#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""作业管理 Celery 适配层。"""

from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from io import BytesIO
import re
import traceback
import zipfile

import pymysql

from oj_modules.db_services import get_class_by_en
from oj_modules.homework.plagiarism import mark_class_plagiarism
from oj_modules.homework.progress import (
    update_export_progress,
    update_plagiarism_progress,
)
from oj_modules.homework.repository import get_student_repository_entries
from oj_modules.homework.runtime import invalidate_problem_list_cache_for_class
from oj_modules.homework.targets import normalize_plagiarism_target
from oj_modules.infrastructure.mysql import get_db_connection, safe_table_name


HOMEWORK_EXPORT_TASK_NAME = "oj.homework.export_codes_with_plagiarism_check_task"
HOMEWORK_PLAGIARISM_TASK_NAME = "oj.homework.mark_plagiarism_task"


@dataclass(frozen=True)
class HomeworkTaskOperations:
    """由组合根注入的作业领域操作，避免 Celery 适配层反向导入路由。"""

    update_export_progress: Callable[..., None]
    get_student_repository_entries: Callable[..., list[dict]]
    normalize_plagiarism_target: Callable[..., dict]
    update_plagiarism_progress: Callable[..., None]
    mark_class_plagiarism: Callable[..., dict]
    invalidate_problem_list_cache_for_class: Callable[..., None]


def build_homework_task_operations(
    redis_client,
    *,
    invalidate_callback=None,
):
    """从 canonical 领域服务构造 Celery 所需操作，保留可替换测试端口。"""

    return HomeworkTaskOperations(
        update_export_progress=partial(update_export_progress, redis_client),
        get_student_repository_entries=get_student_repository_entries,
        normalize_plagiarism_target=normalize_plagiarism_target,
        update_plagiarism_progress=partial(
            update_plagiarism_progress,
            redis_client,
        ),
        mark_class_plagiarism=mark_class_plagiarism,
        invalidate_problem_list_cache_for_class=(
            invalidate_problem_list_cache_for_class
            if invalidate_callback is None
            else invalidate_callback
        ),
    )


def register_homework_admin_tasks(celery_app, binary_redis_client, operations):
    """幂等注册作业导出与查重任务，返回 ``(export, plagiarism)``。"""

    export_task = celery_app.tasks.get(HOMEWORK_EXPORT_TASK_NAME)
    if export_task is None:

        @celery_app.task(bind=True, name=HOMEWORK_EXPORT_TASK_NAME)
        def export_codes_with_plagiarism_check_task(self, selected_class):
            task_id = self.request.id

            try:
                class_info = get_class_by_en(selected_class)
                if not class_info:
                    operations.update_export_progress(task_id, "error", 0, 1, "班级不存在")
                    return None

                operations.update_export_progress(
                    task_id,
                    "collecting",
                    0,
                    100,
                    "开始收集学生代码...",
                )

                conn = get_db_connection()
                try:
                    with conn.cursor() as cursor:
                        cursor.execute(
                            f"SELECT problem_id FROM {safe_table_name(selected_class)} "
                            "ORDER BY id ASC"
                        )
                        homework_problems = cursor.fetchall()
                finally:
                    conn.close()
                if not homework_problems:
                    operations.update_export_progress(
                        task_id,
                        "error",
                        0,
                        1,
                        "该班级没有布置任何作业",
                    )
                    return None

                problem_ids = [
                    problem["problem_id"]
                    for problem in homework_problems
                    if problem.get("problem_id") is not None
                ]
                if not problem_ids:
                    operations.update_export_progress(
                        task_id,
                        "error",
                        0,
                        1,
                        "该班级没有可导出的普通题作业（打榜赛暂不导出代码）",
                    )
                    return None

                problems_map = {}
                conn = get_db_connection()
                try:
                    with conn.cursor() as cursor:
                        placeholders = ",".join(["%s"] * len(problem_ids))
                        cursor.execute(
                            f"SELECT id, title, lang FROM problems "
                            f"WHERE id IN ({placeholders})",
                            problem_ids,
                        )
                        for row in cursor.fetchall():
                            problems_map[row["id"]] = {
                                "title": row["title"],
                                "lang": (row.get("lang") or "matlab").lower(),
                            }
                finally:
                    conn.close()

                conn = get_db_connection()
                try:
                    with conn.cursor() as cursor:
                        cursor.execute(
                            """
                            SELECT u.id, u.username
                            FROM user_class_map m
                            JOIN users u ON u.id = m.user_id
                            WHERE m.class_en = %s
                              AND u.is_admin = 0
                            ORDER BY u.id ASC
                            """,
                            (selected_class,),
                        )
                        students = cursor.fetchall()
                finally:
                    conn.close()
                if not students:
                    operations.update_export_progress(
                        task_id,
                        "error",
                        0,
                        1,
                        "该班级没有学生",
                    )
                    return None

                operations.update_export_progress(
                    task_id,
                    "collecting",
                    10,
                    100,
                    f"找到 {len(students)} 名学生，{len(problem_ids)} 道题目",
                )

                zip_buffer = BytesIO()

                with zipfile.ZipFile(
                    zip_buffer,
                    "w",
                    zipfile.ZIP_DEFLATED,
                ) as zip_file:
                    for index, problem_id in enumerate(problem_ids):
                        problem_metadata = problems_map.get(problem_id, {})
                        problem_title = (
                            problem_metadata.get("title") or f"Problem_{problem_id}"
                        )
                        problem_language = (
                            problem_metadata.get("lang") or "matlab"
                        ).lower()

                        operations.update_export_progress(
                            task_id,
                            "collecting",
                            10 + index * 40 // len(problem_ids),
                            100,
                            f"正在收集题目 {index + 1}/{len(problem_ids)}: {problem_title}",
                        )

                        folder_name = re.sub(r'[\\/*?:"<>|]', "_", problem_title)

                        if problem_language == "matlab":
                            extension = ".m"
                        elif problem_language == "c":
                            extension = ".c"
                        elif problem_language == "cpp":
                            extension = ".cpp"
                        elif problem_language in ("python", "py"):
                            extension = ".py"
                        else:
                            extension = ".txt"

                        conn = get_db_connection()
                        try:
                            with conn.cursor() as cursor:
                                cursor.execute(
                                    """
                                    WITH class_users AS (
                                        SELECT u.id, u.username
                                        FROM user_class_map m
                                        JOIN users u ON u.id = m.user_id
                                        WHERE m.class_en = %s
                                          AND u.is_admin = 0
                                    ),
                                    ranked_submissions AS (
                                        SELECT s.id, s.username, s.code, s.score, s.created_at,
                                               ROW_NUMBER() OVER (
                                                   PARTITION BY cu.id
                                                   ORDER BY s.score DESC, s.created_at DESC
                                               ) AS rn
                                        FROM submissions s
                                        JOIN class_users cu ON cu.username = s.username
                                        WHERE s.problem_id = %s
                                    )
                                    SELECT username, code
                                    FROM ranked_submissions
                                    WHERE rn = 1
                                    ORDER BY username ASC
                                    """,
                                    (selected_class, problem_id),
                                )
                                best_rows = cursor.fetchall()
                        finally:
                            conn.close()

                        for row in best_rows:
                            username = row["username"]
                            code = row.get("code") or ""

                            safe_username = re.sub(r'[\\/*?:"<>|]', "_", username)
                            filename = f"{folder_name}/{safe_username}{extension}"
                            try:
                                info = zipfile.ZipInfo(filename)
                                info.flag_bits |= 0x800
                                zip_file.writestr(info, code.encode("utf-8"))
                            except Exception:
                                info = zipfile.ZipInfo(filename)
                                info.flag_bits |= 0x800
                                zip_file.writestr(info, code)

                    operations.update_export_progress(
                        task_id,
                        "collecting",
                        60,
                        100,
                        "题目代码收集完成，开始收集代码仓库...",
                    )

                    for index, student in enumerate(students):
                        user_id = student["id"]
                        username = student["username"]

                        operations.update_export_progress(
                            task_id,
                            "collecting",
                            60 + index * 30 // len(students),
                            100,
                            f"正在收集 {username} 的代码仓库 "
                            f"({index + 1}/{len(students)})",
                        )

                        repository_files = operations.get_student_repository_entries(
                            user_id
                        )

                        if repository_files:
                            safe_username = re.sub(r'[\\/*?:"<>|]', "_", username)
                            for repository_file in repository_files:
                                filename = (
                                    f"代码仓库/{safe_username}/"
                                    f"{repository_file['filename']}"
                                )
                                if repository_file.get("entry_type") == "directory":
                                    info = zipfile.ZipInfo(filename.rstrip("/") + "/")
                                    info.flag_bits |= 0x800
                                    info.create_system = 3
                                    info.external_attr = (0o40755 & 0xFFFF) << 16
                                    zip_file.writestr(info, b"")
                                    continue
                                try:
                                    info = zipfile.ZipInfo(filename)
                                    info.flag_bits |= 0x800
                                    zip_file.writestr(
                                        info,
                                        repository_file["content"].encode("utf-8"),
                                    )
                                except Exception:
                                    info = zipfile.ZipInfo(filename)
                                    info.flag_bits |= 0x800
                                    zip_file.writestr(
                                        info,
                                        repository_file["content"],
                                    )

                    operations.update_export_progress(
                        task_id,
                        "generating",
                        92,
                        100,
                        "正在生成代码压缩包...",
                    )

                operations.update_export_progress(
                    task_id,
                    "generating",
                    95,
                    100,
                    "准备下载文件...",
                )

                zip_data = zip_buffer.getvalue()
                binary_redis_client.setex(f"export_zip:{task_id}", 600, zip_data)

                operations.update_export_progress(
                    task_id,
                    "completed",
                    100,
                    100,
                    "导出完成",
                )
                return task_id

            except Exception as exc:
                error_message = f"导出失败: {exc}"
                operations.update_export_progress(
                    task_id,
                    "error",
                    0,
                    1,
                    error_message,
                )
                print(traceback.format_exc())
                return None

        export_task = export_codes_with_plagiarism_check_task

    plagiarism_task = celery_app.tasks.get(HOMEWORK_PLAGIARISM_TASK_NAME)
    if plagiarism_task is None:

        @celery_app.task(bind=True, name=HOMEWORK_PLAGIARISM_TASK_NAME)
        def mark_plagiarism_task(self, class_en, mode, threshold, targets):
            task_id = self.request.id
            try:
                class_en = str(class_en or "").strip()
                mode = str(mode or "threshold").strip()
                threshold = float(threshold)
                normalized_targets = []
                for item in targets or []:
                    if isinstance(item, dict):
                        normalized_targets.append(item)
                    else:
                        normalized_targets.append(
                            operations.normalize_plagiarism_target(item)
                        )

                class_info = get_class_by_en(class_en)
                if not class_info:
                    operations.update_plagiarism_progress(
                        task_id,
                        "error",
                        0,
                        1,
                        "班级不存在",
                    )
                    return None

                operations.update_plagiarism_progress(
                    task_id,
                    "collecting",
                    0,
                    100,
                    "正在收集提交材料...",
                )

                def status_callback(stage, current, total, message):
                    operations.update_plagiarism_progress(
                        task_id,
                        stage,
                        current,
                        total,
                        message,
                    )

                def compare_callback(current, total, message):
                    operations.update_plagiarism_progress(
                        task_id,
                        "checking",
                        current,
                        total,
                        message,
                    )

                result = operations.mark_class_plagiarism(
                    class_en,
                    class_info.get("class_cn"),
                    normalized_targets,
                    mode,
                    threshold,
                    progress_callback=compare_callback,
                    status_callback=status_callback,
                )

                operations.invalidate_problem_list_cache_for_class(class_en)
                operations.update_plagiarism_progress(
                    task_id,
                    "completed",
                    100,
                    100,
                    f"标记完成：发现 {result['group_count']} 组，"
                    f"写入 {result['record_count']} 条记录",
                    result=result,
                )
                return result
            except pymysql.Error:
                operations.update_plagiarism_progress(
                    task_id,
                    "error",
                    0,
                    1,
                    "数据库操作失败，请稍后再试",
                )
                return None
            except Exception as exc:
                operations.update_plagiarism_progress(
                    task_id,
                    "error",
                    0,
                    1,
                    f"标记失败: {exc}",
                )
                return None

        plagiarism_task = mark_plagiarism_task

    return export_task, plagiarism_task


__all__ = [
    "HOMEWORK_EXPORT_TASK_NAME",
    "HOMEWORK_PLAGIARISM_TASK_NAME",
    "HomeworkTaskOperations",
    "build_homework_task_operations",
    "register_homework_admin_tasks",
]
