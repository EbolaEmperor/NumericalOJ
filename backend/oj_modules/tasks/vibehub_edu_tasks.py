"""教育作品的普通队列评分适配。"""

from backend.oj_modules.vibehub import edu


def register_vibehub_edu_task(celery_app):
    task = celery_app.tasks.get("oj.vibehub_edu.grade")
    if task is None:
        @celery_app.task(bind=True, name="oj.vibehub_edu.grade", max_retries=3)
        def task(self, submission_id):
            try:
                edu.grade_submission(submission_id)
            except Exception as exc:
                raise self.retry(exc=exc, countdown=10)
    return task
