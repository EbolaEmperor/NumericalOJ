"""批量重测的重置与分发流程，由后台调度任务调用。"""

from backend.oj_modules.db_services import reset_submission_for_rejudge
from backend.oj_modules.submissions.locks import clear_submission_lock, submission_pending_requeue_key
from backend.oj_modules.submissions.written_voting import supersede_latest_attempt


def dispatch_rejudge_submissions(submissions, progress_key, rejudge_task, redis_client):
    # 先预约整批，再将历史记录改成 Pending，避免 watchdog 将错峰等待误判为漏投。
    # TTL 留出整批准备时间、当前记录的错峰时间与恢复宽限；到期后恢复入口仍可兜底。
    for index, submission in enumerate(submissions):
        reserved = redis_client.set(
            submission_pending_requeue_key(submission["id"]),
            progress_key,
            ex=len(submissions) + index + 600,
        )
        if not reserved:
            raise RuntimeError("重测预约写入失败")

    # 保持先重置整批、再投递的顺序；HTTP 请求只提交这一流程的后台任务。
    for submission in submissions:
        if submission.get("status") == "Running":
            clear_submission_lock(submission["id"])
        if int(submission.get("problem_type") or 0) == 2:
            supersede_latest_attempt(submission["id"])
        reset_submission_for_rejudge(submission["id"], submission.get("problem_type"))

    for index, submission in enumerate(submissions):
        rejudge_task.apply_async(
            args=[submission["id"], progress_key],
            countdown=index,
            queue="celery",
        )
        redis_client.hset(progress_key, mapping={"scheduled": index + 1})
