#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Blueprint, request

from oj_modules.api.helpers import apply_limit, clamp_limit, json_error, json_success, public_problem, public_user, to_jsonable
from oj_modules.security.auth import current_user
from oj_modules.problems.promptly import parse_promptly_review_config
from oj_modules.problems.grading import (
    DEFAULT_WRITTEN_GRADING_PROMPT as _DEFAULT_WRITTEN_GRADING_PROMPT,
)
from oj_modules.problems.llm_bindings import (
    get_problem_llm_endpoint_candidates as _problem_llm_endpoint_candidates,
)
from oj_modules.problems.context import (
    build_problem_detail_context,
    build_problem_list_context,
)


problem_api_bp = Blueprint("problem_api", __name__, url_prefix="/api")


def _homework_problem_item(hw, class_en=None, class_cn=None):
    if hw.get("kind") == "ranking":
        return {
            "kind": "ranking",
            "id": hw.get("competition_id"),
            "competition_id": hw.get("competition_id"),
            "title": hw.get("problem_title"),
            "class_en": class_en,
            "class_cn": class_cn,
            "ddl": hw.get("ddl"),
            "complete_count": hw.get("complete_cnt"),
            "is_completed": hw.get("is_completed"),
            "max_score": hw.get("max_score"),
            "url": f"/ranking/{hw.get('competition_id')}/",
        }
    return {
        "kind": "problem",
        "id": hw.get("problem_id"),
        "problem_id": hw.get("problem_id"),
        "title": hw.get("problem_title"),
        "class_en": class_en,
        "class_cn": class_cn,
        "ddl": hw.get("ddl"),
        "complete_count": hw.get("complete_cnt"),
        "is_completed": hw.get("is_completed"),
        "max_score": hw.get("max_score"),
        "total_score": hw.get("total_score"),
        "url": f"/problem/{hw.get('problem_id')}",
    }


def _visible_items_from_context(context):
    if context.get("problems") is not None:
        return [
            {
                "kind": "problem",
                "id": p.get("id"),
                "problem_id": p.get("id"),
                "title": p.get("title"),
                "type": p.get("type"),
                "lang": p.get("lang"),
                "max_score": p.get("max_score"),
                "submission_count": p.get("cnt"),
                "time_limit_ms": p.get("time_limit_ms"),
                "url": f"/problem/{p.get('id')}",
            }
            for p in context.get("problems") or []
        ]

    items = []
    for hw in context.get("homeworks") or []:
        items.append(_homework_problem_item(
            hw,
            class_en=context.get("single_class_en"),
            class_cn=context.get("single_class_cn"),
        ))
    for class_block in context.get("homeworks_by_class") or []:
        for hw in class_block.get("hw_list") or []:
            items.append(_homework_problem_item(
                hw,
                class_en=class_block.get("class_en"),
                class_cn=class_block.get("class_cn"),
            ))
    return items


@problem_api_bp.route("/problems", methods=["GET"])
def problems():
    user = current_user()
    if not user:
        return json_error("请先登录", 401)

    limit = clamp_limit(request.args.get("limit"), default=None)
    context = build_problem_list_context(user)
    items = _visible_items_from_context(context)
    return json_success(
        user=public_user(user),
        view_mode=context.get("view_mode"),
        total_submissions=context.get("total_submissions"),
        total_accepted=context.get("total_accepted"),
        total_grade=context.get("total_grade"),
        last_10_days=context.get("last_10_days"),
        daily_counts=context.get("daily_counts"),
        classes=context.get("classes"),
        single_class_en=context.get("single_class_en"),
        single_class_cn=context.get("single_class_cn"),
        class_grades=context.get("class_grades"),
        homeworks=context.get("homeworks"),
        homeworks_by_class=context.get("homeworks_by_class"),
        problems=apply_limit(items, limit),
        count=len(items),
    )


@problem_api_bp.route("/problems/<int:problem_id>", methods=["GET"])
def problem_detail(problem_id):
    user = current_user()
    if not user:
        return json_error("请先登录", 401)

    context, error_code = build_problem_detail_context(user, problem_id)
    if error_code == "not_found":
        return json_error("题目不存在", 404)
    if error_code == "forbidden":
        return json_error("无权限访问该题目", 403)

    raw_problem = context["problem"]
    problem = public_problem(raw_problem)
    problem_type = int(raw_problem.get("type") or 1)
    written_mode = int(raw_problem.get("written_grading_mode") or 1)
    programming_mode = int(raw_problem.get("programming_grading_mode") or 1)
    is_lean4 = (
        problem_type == 1
        and str(raw_problem.get("lang") or "").strip().lower() in {"lean", "lean4"}
    )
    submit_input_name = (
        "lean_workspace"
        if is_lean4
        else "prompt"
        if problem_type == 1 and programming_mode == 3
        else "code"
        if problem_type == 1
        else "file"
    )
    return json_success(
        problem=problem,
        rendered_content=context["rendered_content"],
        user=public_user(user),
        last_submissions=context["last_submissions"],
        initial_code=context["initial_code"],
        lean_workspace=context.get("lean_workspace"),
        remaining_submissions=context["remaining_submissions"],
        can_submit=context["can_submit"],
        submit_block_code=context["submit_block_code"],
        submit_block_reason=context["submit_block_reason"],
        submit_warning=context.get("submit_warning"),
        homework_assignments=context.get("homework_assignments") or [],
        submit={
            "action": f"/submit/{problem_id}",
            "method": "POST",
            "problem_type": problem_type,
            "programming_grading_mode": programming_mode if problem_type == 1 else None,
            "input_name": submit_input_name,
            "input_kind": (
                "lean_workspace"
                if submit_input_name == "lean_workspace"
                else "prompt"
                if submit_input_name == "prompt"
                else "code"
                if submit_input_name == "code"
                else "file"
            ),
            "accept": None if problem_type == 1 else (".zip" if written_mode == 3 else ".pdf"),
            "help_text": (
                "请提交 prompt，说明解题思路、算法或数据结构及关键边界处理；后台会先审查 prompt，通过后生成代码并评测。"
                if submit_input_name == "prompt"
                else None
                if problem_type == 1
                else (
                    "请上传 zip 文件，压缩包内必须包含 main.tex 及其依赖文件。"
                    if written_mode == 3
                    else "请上传 pdf 文件。"
                )
            ),
        },
    )


@problem_api_bp.route("/problems/<int:problem_id>/submit-context", methods=["GET"])
def submit_context(problem_id):
    return problem_detail(problem_id)


def _problem_form_options():
    return {
        "languages": ["matlab", "c", "cpp", "python", "lean4"],
        "problem_types": [
            {"value": "1", "label": "编程题"},
            {"value": "2", "label": "书面题"},
        ],
        "programming_grading_modes": [
            {"value": 1, "label": "传统交互"},
            {"value": 2, "label": "批改图片"},
            {"value": 3, "label": "Promptly"},
        ],
        "default_written_grading_prompt": _DEFAULT_WRITTEN_GRADING_PROMPT,
        "llm_endpoint_candidates": _problem_llm_endpoint_candidates(),
    }


def _promptly_review_config_from_prompt(prompt_text):
    config = parse_promptly_review_config({"programming_grading_prompt": prompt_text or ""})
    return {
        "brief": config.get("brief") or "",
        "prompt_requirements": config.get("prompt_requirements") or "",
        "example_replies": config.get("example_replies") or [],
        "raw_is_json": bool(config.get("raw_is_json")),
    }


@problem_api_bp.route("/admin/problems/create-form", methods=["GET"])
def problem_create_form():
    user = current_user()
    if not user or user.get("is_admin") != 1:
        return json_error("无权限", 403)
    return json_success(
        user=public_user(user),
        action="/admin/add_problem",
        method="POST",
        defaults={
            "title": "",
            "content": "",
            "initial_code": "",
            "test_code": "",
            "forbidden_func": "",
            "type": "1",
            "lang": "matlab",
            "time_limit": 2000,
            "submission_limit": 10,
            "programming_grading_mode": 1,
            "output_image_filename": "output.png",
            "programming_grading_prompt": "",
            "promptly_review_config": _promptly_review_config_from_prompt(""),
            "written_grading_mode": 1,
            "written_grading_prompt": _DEFAULT_WRITTEN_GRADING_PROMPT,
            "llm_endpoint_bindings": {},
        },
        options=_problem_form_options(),
    )


@problem_api_bp.route("/admin/problems/<int:problem_id>/edit-form", methods=["GET"])
def problem_edit_form(problem_id):
    user = current_user()
    if not user or user.get("is_admin") != 1:
        return json_error("无权限", 403)

    context, error_code = build_problem_detail_context(user, problem_id)
    if error_code == "not_found":
        return json_error("题目不存在", 404)
    if error_code:
        return json_error("无权限", 403)

    problem = context["problem"]
    bindings = dict(problem.get("llm_endpoint_bindings") or {})
    form = {
        "title": problem.get("title") or "",
        "content": problem.get("content") or "",
        "initial_code": problem.get("initial_code") or "",
        "test_code": problem.get("test_code") or "",
        "forbidden_func": problem.get("forbidden_func") or "",
        "lang": problem.get("lang") or "matlab",
        "time_limit": problem.get("time_limit_ms") or 2000,
        "submission_limit": problem.get("submission_limit") or 10,
        "programming_grading_mode": problem.get("programming_grading_mode") or 1,
        "output_image_filename": problem.get("output_image_filename") or "output.png",
        "programming_grading_prompt": problem.get("programming_grading_prompt") or "",
        "promptly_review_config": _promptly_review_config_from_prompt(problem.get("programming_grading_prompt") or ""),
        "written_grading_mode": problem.get("written_grading_mode") or 1,
        "written_grading_prompt": problem.get("written_grading_prompt") or "",
        "llm_endpoint_bindings": bindings,
    }
    form.update({key: value for key, value in bindings.items()})
    api_problem = dict(problem)
    api_problem.pop("programming_grading_model", None)
    api_problem.pop("written_grading_model", None)
    return json_success(
        user=public_user(user),
        problem=to_jsonable(api_problem),
        form=form,
        lean_workspace=context.get("lean_workspace"),
        action=f"/admin/edit_problem/{problem_id}",
        method="POST",
        options=_problem_form_options(),
    )
