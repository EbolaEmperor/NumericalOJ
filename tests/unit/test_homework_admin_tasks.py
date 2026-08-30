from types import SimpleNamespace
from unittest.mock import Mock

from backend.oj_modules.homework import plagiarism, repository, targets
from backend.oj_modules.tasks import homework_admin_tasks


class _FakeCelery:
    def __init__(self):
        self.tasks = {}
        self.registrations = []

    def task(self, **options):
        def decorator(function):
            self.registrations.append(options)
            self.tasks[options["name"]] = function
            return function

        return decorator


def _operations():
    return homework_admin_tasks.HomeworkTaskOperations(
        update_export_progress=Mock(),
        get_student_repository_entries=Mock(return_value=[]),
        normalize_plagiarism_target=Mock(),
        update_plagiarism_progress=Mock(),
        mark_class_plagiarism=Mock(),
        invalidate_problem_list_cache_for_class=Mock(),
    )


def test_homework_task_operations_are_built_from_canonical_domain_services():
    redis_client = Mock()
    invalidator = Mock()

    operations = homework_admin_tasks.build_homework_task_operations(
        redis_client,
        invalidate_callback=invalidator,
    )

    assert operations.get_student_repository_entries is repository.get_student_repository_entries
    assert operations.normalize_plagiarism_target is targets.normalize_plagiarism_target
    assert operations.mark_class_plagiarism is plagiarism.mark_class_plagiarism
    assert operations.invalidate_problem_list_cache_for_class is invalidator

    operations.update_export_progress("task-1", "running", 1, 2, "处理中")
    redis_client.setex.assert_called_once()


def test_homework_task_registration_is_idempotent_and_preserves_names():
    celery = _FakeCelery()
    operations = _operations()
    binary_redis = Mock()

    first = homework_admin_tasks.register_homework_admin_tasks(
        celery,
        binary_redis,
        operations,
    )
    second = homework_admin_tasks.register_homework_admin_tasks(
        celery,
        binary_redis,
        operations,
    )

    assert second == first
    assert set(celery.tasks) == {
        "oj.homework.export_codes_with_plagiarism_check_task",
        "oj.homework.mark_plagiarism_task",
    }
    assert celery.registrations == [
        {
            "bind": True,
            "name": "oj.homework.export_codes_with_plagiarism_check_task",
        },
        {"bind": True, "name": "oj.homework.mark_plagiarism_task"},
    ]


def test_homework_tasks_report_missing_class_without_touching_storage(monkeypatch):
    celery = _FakeCelery()
    operations = _operations()
    binary_redis = Mock()
    monkeypatch.setattr(homework_admin_tasks, "get_class_by_en", lambda _value: None)
    export_task, plagiarism_task = (
        homework_admin_tasks.register_homework_admin_tasks(
            celery,
            binary_redis,
            operations,
        )
    )
    bound_task = SimpleNamespace(request=SimpleNamespace(id="task-1"))

    assert export_task(bound_task, "Cmissing") is None
    assert plagiarism_task(
        bound_task,
        "Cmissing",
        "threshold",
        0.9,
        [],
    ) is None

    operations.update_export_progress.assert_called_once_with(
        "task-1",
        "error",
        0,
        1,
        "班级不存在",
    )
    operations.update_plagiarism_progress.assert_called_once_with(
        "task-1",
        "error",
        0,
        1,
        "班级不存在",
    )
    binary_redis.setex.assert_not_called()
