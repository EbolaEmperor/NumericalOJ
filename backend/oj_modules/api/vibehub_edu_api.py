"""教育作答的登录态 API；iframe 使用同一领域服务的租约入口。"""

from flask import Blueprint, request

from backend.oj_modules.api.helpers import json_success
from backend.oj_modules.security.auth import current_user
from backend.oj_modules.vibehub import edu, services
from backend.oj_modules.vibehub.runtime import VibeHubRuntimeError


vibehub_edu_api_bp = Blueprint("vibehub_edu_api", __name__, url_prefix="/api/vibehub")


def _user():
    actor = current_user()
    if not actor:
        raise services.VibeHubPermissionError("请先登录")
    return actor


@vibehub_edu_api_bp.errorhandler(services.VibeHubError)
def _error(exc):
    return {"success": False, "message": str(exc), "code": exc.code}, exc.status_code


@vibehub_edu_api_bp.errorhandler(VibeHubRuntimeError)
def _runtime_error(_exc):
    return {"success": False, "message": "作品运行服务暂时不可用，请稍后重试。"}, 503


def _payload():
    request.max_content_length = 128 * 1024
    if request.content_length and request.content_length > 128 * 1024:
        raise services.VibeHubError("请求过大", status_code=413)
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise services.VibeHubError("请求必须为 JSON 对象")
    return payload


@vibehub_edu_api_bp.post("/projects/<slug>/edu/launch")
def launch(slug):
    actor = _user()
    payload = _payload()
    if set(payload) - {"assignment_id", "channel"}:
        raise services.VibeHubError("启动参数无效")
    assignment_id = payload.get("assignment_id")
    if assignment_id is not None and (type(assignment_id) is not int or assignment_id <= 0):
        raise services.VibeHubError("作业编号无效")
    return json_success(**edu.launch(slug, actor, assignment_id, channel=payload.get("channel", "public")))


@vibehub_edu_api_bp.get("/edu/projects")
def projects():
    return json_success(projects=edu.list_assignable_projects(_user()))


@vibehub_edu_api_bp.get("/edu/attempts/<attempt_id>")
def state(attempt_id):
    return json_success(**edu.attempt_state(attempt_id, _user()))


@vibehub_edu_api_bp.post("/edu/attempts/<attempt_id>/actions")
def action(attempt_id):
    return json_success(**edu.apply_action(attempt_id, _payload(), _user()))


@vibehub_edu_api_bp.post("/edu/attempts/<attempt_id>/submit")
def submit(attempt_id):
    return json_success(**edu.submit(attempt_id, _payload(), _user()))


@vibehub_edu_api_bp.post("/edu/continue")
def continue_attempt():
    actor = _user()
    payload = _payload()
    if set(payload) != {"lease_token", "request_id", "expected_attempt_id"}:
        raise services.VibeHubError("继续作答请求字段无效")
    return json_success(**edu.continue_attempt(payload["lease_token"],
        {"request_id": payload["request_id"], "expected_attempt_id": payload["expected_attempt_id"]}, actor))


@vibehub_edu_api_bp.get("/edu/attempts/<attempt_id>/result")
def attempt_result(attempt_id):
    return json_success(**edu.submission_result(attempt_id=attempt_id, actor=_user()))


@vibehub_edu_api_bp.get("/edu/submissions/<int:submission_id>")
def result(submission_id):
    return json_success(**edu.submission_result(submission_id, actor=_user()))
