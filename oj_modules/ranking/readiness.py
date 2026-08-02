"""打榜赛提交前的配置就绪校验。"""

import os

import config as _cfg
from oj_modules.ranking.agent_judge.db import (
    list_agent_judge_endpoints,
    list_competition_rules,
    list_quality_gate_endpoints,
)
from oj_modules.ranking.batch import PLACEHOLDER, USERNAME_RE
from oj_modules.ranking.presentation import competition_scoring_mode


def configured_file(path):
    path = str(path or "").strip()
    return bool(path and os.path.isfile(path))


def agent_judge_endpoint_ready(competition_id, comp):
    """端点池中是否至少有一个启用的 Agent 评测端点。"""
    try:
        return bool(list_agent_judge_endpoints(competition_id, enabled_only=True))
    except Exception:
        return False


def quality_gate_endpoint_ready(competition_id):
    try:
        return bool(list_quality_gate_endpoints(competition_id, enabled_only=True))
    except Exception:
        return False


def reverse_quality_gate_enabled(comp):
    value = (comp or {}).get("reverse_quality_gate_enabled")
    return value is True or str(value or "").strip().lower() in (
        "1", "true", "on", "yes",
    )


def reverse_quality_gate_block_reason(competition_id, comp):
    if not reverse_quality_gate_enabled(comp):
        return ""
    if not str((comp or {}).get("reverse_quality_gate_prompt") or "").strip():
        return "该比赛已启用质量门禁，但管理员尚未设置审核标准，暂时无法提交。"
    if not quality_gate_endpoint_ready(competition_id):
        return "该比赛已启用质量门禁，但管理员尚未配置质量门禁端点，暂时无法提交。"
    return ""


def reverse_quality_gate_ready(competition_id, comp):
    return not reverse_quality_gate_block_reason(competition_id, comp)


def fake_agent_judge_enabled():
    raw = os.getenv("NUMOJ_FAKE_AGENT_JUDGE")
    if raw is None:
        raw = getattr(_cfg, "NUMOJ_FAKE_AGENT_JUDGE", False)
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def ranking_submit_block_reason(comp, competition_id, user=None):
    if not comp:
        return "比赛不存在或已被删除"
    is_admin = bool(user and user.get("is_admin") == 1)
    if not is_admin and comp.get("is_active") != 1:
        return "该比赛未开放"

    scoring_mode = competition_scoring_mode(comp)
    if scoring_mode == "absolute":
        missing_reference = not configured_file(comp.get("reference_answer_path"))
        missing_script = not configured_file(comp.get("scoring_script_path"))
        if missing_reference and missing_script:
            return "该比赛为标准答案评分模式，但管理员尚未上传标准答案和评测脚本，暂时无法提交。"
        if missing_reference:
            return "该比赛为标准答案评分模式，但管理员尚未上传标准答案，暂时无法提交。"
        if missing_script:
            return "该比赛为标准答案评分模式，但管理员尚未上传评测脚本，暂时无法提交。"
        return ""

    if scoring_mode == "elo":
        if not configured_file(comp.get("scoring_script_path")):
            return "该比赛为 ELO 模式，但管理员尚未上传评测脚本，暂时无法提交。"
        return ""

    if scoring_mode == "agent_judge":
        if not fake_agent_judge_enabled():
            if not agent_judge_endpoint_ready(competition_id, comp):
                return "该比赛为 Agent 评测模式，但管理员尚未配置模型端点，暂时无法提交。"
            if not list_competition_rules(competition_id):
                return "该比赛尚未设置评分规则，暂时无法提交。"
        method = (comp.get("submission_method") or "zip").strip().lower()
        if method == "git":
            template = (comp.get("git_format") or "").strip()
            if not template or PLACEHOLDER not in template:
                return "该比赛启用 Git 提交方式，但管理员尚未配置 Git 仓库标准命名，暂时无法提交。"
            if user:
                username = (user.get("username") or "").strip()
                if not USERNAME_RE.match(username):
                    return "你的用户名不符合 Git 仓库命名要求，暂时无法提交。"
        return ""

    if scoring_mode == "reverse_judge":
        if not agent_judge_endpoint_ready(competition_id, comp):
            return "该比赛为反向评测模式，但管理员尚未配置模型端点，暂时无法提交。"
        return reverse_quality_gate_block_reason(competition_id, comp)

    return "该比赛评分模式配置异常，暂时无法提交。"


__all__ = [
    "configured_file",
    "agent_judge_endpoint_ready",
    "quality_gate_endpoint_ready",
    "reverse_quality_gate_enabled",
    "reverse_quality_gate_block_reason",
    "reverse_quality_gate_ready",
    "fake_agent_judge_enabled",
    "ranking_submit_block_reason",
]
