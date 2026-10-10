"""FaithSieve 管理页查询与显式恢复 API；鉴权先于数据库和工件读取。"""

from flask import Blueprint, request

from backend.oj_modules.api.helpers import clamp_page, json_error, json_success, page_numbers
from backend.oj_modules.security.auth import current_user, is_admin
from backend.oj_modules.shared.markdown import render_rich_markdown
from backend.oj_modules.faithsieve.services import can_retry_failed_run, retry_failed_run
from backend.oj_modules.faithsieve.recovery import FaithSieveRecoveryConflict, FaithSieveRecoveryDispatchError, FaithSieveRecoveryError
from backend.oj_modules.faithsieve.costs import load_run_costs, unknown_cost
from backend.oj_modules.submissions.faithsieve_views import (
    get_faithsieve_detail, get_faithsieve_run, list_faithsieve_runs, valid_attempt_id,
)


faithsieve_api_bp = Blueprint("faithsieve_api", __name__, url_prefix="/api/admin/faithsieve")


@faithsieve_api_bp.after_request
def _private_response(response):
    response.headers["Cache-Control"] = "private, no-store"
    return response


def _require_admin():
    user = current_user()
    if not user:
        return json_error("请先登录", 401)
    if not is_admin(user):
        return json_error("无权限", 403)
    return None


def workflow_snapshot(run):
    if run.get("execution_mode") == "skill":
        from backend.oj_modules.faithsieve.skill_views import skill_snapshot
        return skill_snapshot(run)
    from backend.oj_modules.faithsieve.views import workflow_snapshot as snapshot
    return snapshot(run)


def read_artifact(run, path, *, stage_key=None):
    if run.get("execution_mode") == "skill":
        from backend.oj_modules.faithsieve.skill_views import read_skill_artifact
        return read_skill_artifact(run, path, stage_key=stage_key)
    from backend.oj_modules.faithsieve.views import read_artifact as read
    return read(run, path, stage_key=stage_key)


@faithsieve_api_bp.get("")
def faithsieve_list():
    error = _require_admin()
    if error is not None:
        return error
    try:
        data = list_faithsieve_runs(
            page=clamp_page(request.args.get("page", 1)), status=request.args.get("status"),
            username=request.args.get("username"), problem_id=request.args.get("problem_id"),
            submission_id=request.args.get("submission_id"),
        )
    except ValueError as exc:
        return json_error(str(exc), 400)
    return json_success(**data, page_numbers=page_numbers(data["page"], data["total_pages"]))


@faithsieve_api_bp.get("/<attempt_id>")
def faithsieve_detail(attempt_id):
    error = _require_admin()
    if error is not None:
        return error
    if not valid_attempt_id(attempt_id):
        return json_error("FaithSieve 评测记录不存在", 404)
    data = get_faithsieve_detail(attempt_id)
    if data is None:
        return json_error("FaithSieve 评测记录不存在", 404)
    try:
        cost = load_run_costs([data["run"]]).get(attempt_id, unknown_cost())
    except Exception:
        # 费用读取故障只降级费用，不能挡住证明、进度和已完成结果。
        cost = unknown_cost()
    data["run"] = {**data["run"], "cost": cost}
    data["run"] = {**data["run"], "retry_eligible": bool(
        data["run"].get("status") == "failed" and data["run"].get("execution_mode") == "workflow"
        and can_retry_failed_run(attempt_id)
    )}
    try:
        data["workflow"] = workflow_snapshot(data["run"])
    except (OSError, ValueError):
        data["workflow"] = {
            "stages": [], "source": {}, "artifacts": [], "edges": [],
            "summary": {"stage_count": 0, "shown_stage_count": 0, "truncated": False},
            "warnings": ["评测工件暂不可读取"],
        }
    workflow = data["workflow"]
    data["workflow"] = {
        **workflow,
        "stages": [
            {**stage, "report_html": render_rich_markdown(stage["report"])}
            if isinstance(stage.get("report"), str) and stage["report"].strip()
            else stage
            for stage in workflow.get("stages", [])
        ],
    }
    result = data.get("result")
    if isinstance(result, dict) and isinstance(result.get("comment"), str) and result["comment"].strip():
        result = {**result, "comment_html": render_rich_markdown(result["comment"])}
        data["result"] = result
        data["run"] = {**data["run"], "result": result}
    return json_success(**data)


@faithsieve_api_bp.post("/<attempt_id>/retry")
def faithsieve_retry(attempt_id):
    error = _require_admin()
    if error is not None:
        return error
    if not valid_attempt_id(attempt_id):
        return json_error("FaithSieve 评测记录不存在", 404)
    body = request.get_data(cache=True)
    if body and (not request.is_json or request.get_json(silent=True) != {}):
        return json_error("恢复请求不能包含模型、参数或额外输入", 400)
    try:
        result = retry_failed_run(attempt_id, actor=current_user()["username"])
    except FaithSieveRecoveryConflict as exc:
        return json_error(str(exc), 409)
    except FaithSieveRecoveryDispatchError as exc:
        return json_error(str(exc), 503)
    except FaithSieveRecoveryError as exc:
        return json_error(str(exc), 400)
    except (OSError, ValueError):
        return json_error("原评测输入或恢复材料无法确认", 400)
    except Exception:
        return json_error("FaithSieve 恢复暂不可用，请重新读取记录", 503)
    return json_success(**result)


@faithsieve_api_bp.get("/<attempt_id>/artifacts")
def faithsieve_artifact(attempt_id):
    error = _require_admin()
    if error is not None:
        return error
    if not valid_attempt_id(attempt_id):
        return json_error("FaithSieve 评测记录不存在", 404)
    run = get_faithsieve_run(attempt_id)
    if run is None:
        return json_error("FaithSieve 评测记录不存在", 404)
    path = request.args.get("path") or ""
    stage_key = request.args.get("stage_key") or None
    try:
        artifact = read_artifact(run, path, stage_key=stage_key)
    except (OSError, ValueError):
        return json_error("工件不存在或不可读取", 404)
    if artifact is None:
        return json_error("工件不存在或不可读取", 404)
    if artifact.get("language") == "markdown":
        artifact = {**artifact, "content_html": render_rich_markdown(artifact.get("content"))}
    return json_success(artifact=artifact)
