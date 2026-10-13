"""提交评分的请求级可见性投影；不修改数据库或内部判题快照。"""

from backend.oj_modules.submissions.written_voting import REVIEW_REQUIRED_STATES

GRADING_NOT_PUBLIC_STATUS = "评分未公开"
JUDGING_STATUSES = frozenset({"Pending", "Waiting", "Running", "Generating"})


def _integer(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def submission_is_judging(submission, vote_attempt=None):
    """用未脱敏的数据判断评测进度，隐藏分数不代表评测仍在运行。"""
    if vote_attempt and str(vote_attempt.get("status") or "") in REVIEW_REQUIRED_STATES:
        return False
    return submission.get("status") in JUDGING_STATUSES or submission.get("score") is None


def grading_results_visible(user, problem):
    """管理员始终可见；仅 AI 书面题遵守当前题目的公开评分开关。"""
    # 数据访问层也可使用本模块，避免导入时经认证模块反向加载 db_services。
    from backend.oj_modules.security.auth import is_admin

    if is_admin(user):
        return True
    problem = problem or {}
    problem_type = _integer(problem.get("type", problem.get("problem_type")), 0)
    grading_mode = _integer(problem.get("written_grading_mode"), 1)
    if problem_type != 2 or grading_mode not in {1, 2, 3}:
        return True
    # 旧题和未显式设置的题目沿用原有公开行为。
    return bool(_integer(problem.get("written_score_public"), 1))


def project_submission_grading(submission, problem, user):
    """鉴权之后调用，返回不会泄露隐藏分数、评语和通过状态的副本。"""
    projected = dict(submission or {})
    if problem is None and _integer(projected.get("problem_type"), 0) == 2:
        # 题目被撤下或旧快照已无法回源时，不开放历史书面评语。
        problem = {"type": 2, "written_score_public": 0}
    if "problem_type" in projected and not _integer(projected.get("problem_type"), 0):
        projected["problem_type"] = (problem or {}).get("type")
    visible = grading_results_visible(user, problem)
    projected["result_visible"] = visible
    if visible:
        return projected

    projected.update({
        "score": None,
        "code": "",
        "written_comment": "",
        "written_vote": None,
        "is_ac": False,
    })
    # 历史解析异常可能含模型原始评分输出，不能把它当成原稿转写公开。
    for field in (
        "submission_latex_error", "written_latex_error",
        "prompt_generation_error", "promptly_review_reply",
    ):
        if field in projected:
            projected[field] = ""
    if projected.get("status") not in JUDGING_STATUSES:
        projected["status"] = GRADING_NOT_PUBLIC_STATUS
    # 书面题原稿文件名继续保留；结构化测试点可能携带判分结果。
    if isinstance(projected.get("test_points"), list):
        projected["test_points"] = [
            point for point in projected["test_points"] if isinstance(point, str)
        ]
        projected["test_points_count"] = len(projected["test_points"])
    return projected
