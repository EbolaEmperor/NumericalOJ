from unittest.mock import Mock, call

from oj_modules.tasks import rejudge_tasks


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


def test_rejudge_task_registration_is_idempotent_and_preserves_name():
    celery = _FakeCelery()
    redis_client = Mock()
    evaluate_task = Mock()
    written_task = Mock()

    first = rejudge_tasks.register_rejudge_task(
        celery,
        redis_client,
        evaluate_task,
        written_task,
    )
    second = rejudge_tasks.register_rejudge_task(
        celery,
        redis_client,
        evaluate_task,
        written_task,
    )

    assert second is first
    assert celery.registrations == [
        {"name": "oj.rejudge.evaluate_submission_and_update"}
    ]


def test_rejudge_task_dispatches_by_problem_type_and_updates_progress(monkeypatch):
    celery = _FakeCelery()
    redis_client = Mock()
    evaluate_task = Mock()
    written_task = Mock()
    submissions = {
        1: {"problem_type": 1},
        2: {"problem_type": 2},
    }
    monkeypatch.setattr(
        rejudge_tasks,
        "get_submission_by_id",
        submissions.get,
    )
    task = rejudge_tasks.register_rejudge_task(
        celery,
        redis_client,
        evaluate_task,
        written_task,
    )

    task(1, "rejudge:1")
    task(2, "rejudge:2")

    evaluate_task.assert_called_once_with(1)
    written_task.assert_called_once_with(2)
    assert redis_client.hincrby.call_args_list == [
        call("rejudge:1", "done", 1),
        call("rejudge:2", "done", 1),
    ]


def test_rejudge_task_updates_progress_when_dispatch_fails(monkeypatch):
    celery = _FakeCelery()
    redis_client = Mock()
    evaluate_task = Mock(side_effect=RuntimeError("failed"))
    monkeypatch.setattr(
        rejudge_tasks,
        "get_submission_by_id",
        lambda _submission_id: {"problem_type": 1},
    )
    task = rejudge_tasks.register_rejudge_task(
        celery,
        redis_client,
        evaluate_task,
    )

    try:
        task(3, "rejudge:3")
    except RuntimeError as exc:
        assert str(exc) == "failed"
    else:
        raise AssertionError("task should propagate dispatch failure")

    redis_client.hincrby.assert_called_once_with("rejudge:3", "done", 1)
