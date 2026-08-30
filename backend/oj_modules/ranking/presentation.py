"""打榜赛 Web/API 共用的纯展示与格式化约定。"""

from backend.oj_modules.ranking.agent_judge.db import normalize_endpoint_model_capabilities
from backend.oj_modules.shared.markdown import render_rich_markdown


ALLOWED_TABS = (
    "description", "submit", "leaderboard", "matches", "all_submissions",
    "appeals", "edit", "batch_eval",
)
SUBMISSIONS_PER_PAGE = 50
MATCHES_PER_PAGE = 20
ALLOWED_ANSWER_FORMATS = ("json", "zip")
ALLOWED_SCORING_MODES = ("absolute", "elo", "agent_judge", "reverse_judge")


def normalize_answer_format(value, default="json"):
    fmt = str(value or "").strip().lower()
    return fmt if fmt in ALLOWED_ANSWER_FORMATS else default


def competition_answer_format(comp):
    return normalize_answer_format((comp or {}).get("answer_format"))


def normalize_scoring_mode(value, default="absolute"):
    mode = str(value or "").strip().lower()
    return mode if mode in ALLOWED_SCORING_MODES else default


def competition_scoring_mode(comp):
    return normalize_scoring_mode((comp or {}).get("scoring_mode"))


def masked_agent_endpoints(endpoints):
    """管理端可见的端点配置；密钥仅返回是否已配置。"""
    return [
        {
            "id": endpoint["id"],
            "harness": endpoint.get("harness") or "claude_code",
            "protocol": endpoint.get("protocol"),
            "effective_protocol": endpoint.get("effective_protocol") or "",
            "base_url": endpoint.get("base_url") or "",
            "model": endpoint.get("model") or "",
            **normalize_endpoint_model_capabilities(endpoint),
            "thinking_format": endpoint.get("thinking_format") or "none",
            "concurrency_limit": int(endpoint.get("concurrency_limit") or 1),
            "status": endpoint.get("status") or "enabled",
            "enabled": endpoint.get("enabled"),
            "has_key": bool(endpoint.get("api_key")),
        }
        for endpoint in (endpoints or [])
    ]


def submission_quota_message(quota):
    return (
        f"本轮提交次数已用完（每 48 小时上限 {quota['limit']} 次），"
        f"将于 {quota['next_reset']:%Y-%m-%d %H:%M} 刷新。"
    )


def page_window(current_page, total_pages, radius=5):
    start = max(1, current_page - radius)
    end = min(total_pages, current_page + radius)
    return list(range(start, end + 1))


def render_description(text):
    return render_rich_markdown(text)


__all__ = [
    "ALLOWED_TABS",
    "SUBMISSIONS_PER_PAGE",
    "MATCHES_PER_PAGE",
    "ALLOWED_ANSWER_FORMATS",
    "ALLOWED_SCORING_MODES",
    "normalize_answer_format",
    "competition_answer_format",
    "normalize_scoring_mode",
    "competition_scoring_mode",
    "masked_agent_endpoints",
    "submission_quota_message",
    "page_window",
    "render_description",
]
