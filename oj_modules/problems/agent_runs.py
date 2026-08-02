"""Agent 解题任务在管理页面与 JSON API 中共用的展示字段。"""


def decorate_agent_run_summaries(runs):
    """原地补充任务摘要展示字段，并返回原列表。"""
    for run in runs:
        run["display_problem_title"] = (
            str(run.get("problem_title") or "").strip()
            or f"Problem {run.get('problem_id') or '-'}"
        )
        run["display_status"] = str(run.get("status") or "Pending")
        run["display_rounds"] = f"{int(run.get('rounds_run') or 0)}"
        run["display_best_score"] = int(run.get("best_score") or 0)
    return runs


__all__ = ["decorate_agent_run_summaries"]
