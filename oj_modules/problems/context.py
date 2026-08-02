#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""题目列表、总题库与题目详情的领域上下文组装。"""

from datetime import datetime

from oj_modules.classroom.dashboard import (
    attach_submission_metrics,
    get_class_activity,
    get_problem_submission_metrics,
    select_visible_class,
    visible_classes_for_user_cached,
)
from oj_modules.classroom.logos import attach_class_logos
from oj_modules.db_services import (
    can_submit,
    get_all_problems,
    get_last_10_days_counts_from_counter,
    get_problem,
    get_remaining_submissions,
    get_submission_summaries_by_user_and_problem,
)
from oj_modules.problems.catalog import (
    _get_homeworks_for_classes,
    get_homeworks,
    get_homeworks_and_grades_map,
    get_today_submission_counts,
    get_user_classes_cached,
)
from oj_modules.shared.markdown import render_rich_markdown


__all__ = (
    "build_problem_detail_context",
    "build_problem_library_context",
    "build_problem_list_context",
)


def _base_problem_list_context():
    total_submissions, total_accepted = get_today_submission_counts()
    last_10_days, daily_counts = get_last_10_days_counts_from_counter()
    return {
        "total_submissions": total_submissions,
        "total_accepted": total_accepted,
        "total_grade": 100,
        "last_10_days": last_10_days,
        "daily_counts": daily_counts,
        "now": datetime.now(),
    }


def _selected_class_context(context, classes, requested_class_en):
    selected_class = select_visible_class(classes, requested_class_en)
    context["selected_class"] = selected_class
    context["selected_class_en"] = (
        selected_class.get("class_en") if selected_class else None
    )
    context["selected_class_cn"] = (
        selected_class.get("class_cn") if selected_class else None
    )
    return selected_class


def build_problem_list_context(
    user,
    *,
    admin_class_view=False,
    selected_class_en=None,
    include_dashboard=False,
    include_class_activity=True,
):
    """
    组装题库页的完整数据上下文。
    HTML 页面和 JSON API 共用这里，避免 CLI 再从模板 HTML 里反向解析信息。
    """
    context = _base_problem_list_context()
    context["user"] = user

    if user['is_admin'] == 1 and not admin_class_view:
        context["problems"] = get_all_problems()
        context["view_mode"] = "admin"
        return context

    if user['is_admin'] == 1:
        classes = attach_class_logos(visible_classes_for_user_cached(user))
        context["classes"] = classes
        # 旧移动端仍使用管理员总题库列表；桌面端使用下面的班级作业上下文。
        context["problems"] = get_all_problems()
        selected_class = _selected_class_context(context, classes, selected_class_en)
        if not selected_class:
            context.update({
                "selected_homeworks": [],
                "class_activity": [],
                "view_mode": "admin_class_empty",
            })
            return context

        class_en = selected_class["class_en"]
        selected_homeworks = _get_homeworks_for_classes(
            user["id"], [class_en], username=user.get("username")
        ).get(class_en, [])
        context.update({
            "selected_homeworks": attach_submission_metrics(
                selected_homeworks, class_en=class_en
            ),
            "class_activity": (
                get_class_activity(class_en) if include_class_activity else []
            ),
            "view_mode": "admin_class",
        })
        return context

    classes = attach_class_logos(get_user_classes_cached(user['id']))
    context["classes"] = classes

    if not classes:
        context["homeworks"] = []
        if include_dashboard:
            context["selected_homeworks"] = []
            context["class_activity"] = []
        context["view_mode"] = "student_empty"
        return context

    if len(classes) == 1:
        cls = classes[0]['class_en']
        homeworks_map, grades_map = get_homeworks_and_grades_map(user['id'], user['username'], [cls])
        homeworks = homeworks_map.get(cls, [])
        context.update({
            "homeworks": homeworks,
            "single_class_en": cls,
            "single_class_cn": classes[0]['class_cn'],
            "class_grades": grades_map.get(cls),
            "view_mode": "student_single_class",
        })
        if include_dashboard:
            dashboard_homeworks = attach_submission_metrics(
                homeworks,
                class_en=cls,
            )
            context.update({
                "selected_class": classes[0],
                "selected_class_en": cls,
                "selected_class_cn": classes[0]['class_cn'],
                "selected_homeworks": dashboard_homeworks,
                "class_activity": (
                    get_class_activity(cls) if include_class_activity else []
                ),
            })
        return context

    class_en_list = [c['class_en'] for c in classes]
    class_homeworks_map, class_grades_map = get_homeworks_and_grades_map(
        user['id'],
        user['username'],
        class_en_list,
    )

    homeworks_by_class = []
    for c in classes:
        items = class_homeworks_map.get(c['class_en'], [])
        grades = class_grades_map.get(c['class_en'])
        homeworks_by_class.append({
            "class_en": c['class_en'],
            "class_cn": c['class_cn'],
            "hw_list": items,
            "grades": grades,
        })

    context["homeworks_by_class"] = homeworks_by_class
    context["view_mode"] = "student_multi_class"
    if not include_dashboard:
        return context

    selected_class = _selected_class_context(context, classes, selected_class_en)
    selected_homeworks = []
    if selected_class:
        for block in homeworks_by_class:
            if block["class_en"] == selected_class["class_en"]:
                selected_homeworks = block["hw_list"]
                break
        selected_homeworks = attach_submission_metrics(
            selected_homeworks, class_en=selected_class["class_en"]
        )
    context["selected_homeworks"] = selected_homeworks
    context["class_activity"] = (
        get_class_activity(selected_class["class_en"])
        if selected_class and include_class_activity
        else []
    )
    return context


def build_problem_library_context(user):
    """构造管理员总题库桌面视图，不混入班级 DDL。"""
    context = _base_problem_list_context()
    problems = [dict(problem) for problem in (get_all_problems() or [])]
    metrics = get_problem_submission_metrics(
        [problem.get("id") for problem in problems]
    )
    for problem in problems:
        problem["submission_metrics"] = metrics.get(int(problem["id"]))
    context.update({
        "user": user,
        "problems": problems,
        "view_mode": "admin_library",
    })
    return context


def _get_selected_problem_homework(user, class_en, problem_id):
    """仅从用户可见的指定班级读取普通题作业。"""
    if not class_en:
        return None
    selected_class = select_visible_class(
        visible_classes_for_user_cached(user), class_en
    )
    if not selected_class or selected_class.get("class_en") != class_en:
        return None
    class_homeworks = _get_homeworks_for_classes(
        user["id"], [class_en], username=user.get("username")
    ).get(class_en, [])
    return next(
        (
            item for item in class_homeworks
            if item.get("kind") == "problem"
            and item.get("problem_id") == problem_id
        ),
        None,
    )


def build_problem_detail_context(user, problem_id, selected_class_en=None):
    """
    组装题目详情页的完整数据上下文。
    返回 (context, error_code)，error_code 为 not_found / forbidden / None。
    """
    problem = get_problem(problem_id)
    if not problem:
        return None, "not_found"

    homework = None
    if user['is_admin'] != 1:
        homeworks = get_homeworks(user)
        homework = next(
            (item for item in homeworks if item['problem_id'] == problem_id),
            None,
        )
        if homework is None:
            return None, "forbidden"
        selected_homework = _get_selected_problem_homework(
            user, selected_class_en, problem_id
        )
        if selected_homework:
            homework = selected_homework
    elif selected_class_en:
        homework = _get_selected_problem_homework(
            user, selected_class_en, problem_id
        )

    rendered_content = render_rich_markdown(problem['content'])

    # 题目详情页只展示最近 3 条提交，直接用 LIMIT 取，避免把该用户该题的全部提交拉进内存。
    last_submissions = get_submission_summaries_by_user_and_problem(user['username'], problem_id, limit=3)
    initial_code = problem.get('initial_code', '')

    submission_limit = problem.get('submission_limit', 10)
    remaining_submissions = (
        get_remaining_submissions(user['username'], problem_id, submission_limit)
        if user['is_admin'] != 1
        else None
    )
    can_submit_flag = (
        can_submit(user['username'], problem_id, submission_limit)
        if user['is_admin'] != 1
        else True
    )

    return {
        "problem": problem,
        "rendered_content": rendered_content,
        "user": user,
        "last_submissions": last_submissions,
        "initial_code": initial_code,
        "remaining_submissions": remaining_submissions,
        "can_submit": can_submit_flag,
        "homework": homework,
    }, None
