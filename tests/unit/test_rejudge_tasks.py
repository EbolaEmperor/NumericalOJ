from unittest.mock import Mock, call

from backend.oj_modules.tasks import rejudge_tasks
from backend.oj_modules.submissions import rejudge_dispatch
import pytest


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


def test_bulk_rejudge_registration_is_idempotent_and_does_not_retry_worker_loss():
    celery = _FakeCelery()
    redis_client = Mock()
    single_task = Mock()

    first = rejudge_tasks.register_bulk_rejudge_task(celery, redis_client, single_task)
    second = rejudge_tasks.register_bulk_rejudge_task(celery, redis_client, single_task)

    assert second is first
    assert celery.registrations == [{
        "name": "oj.rejudge.dispatch_batch",
        "queue": "celery",
        "acks_late": False,
        "reject_on_worker_lost": False,
    }]


def test_bulk_rejudge_resets_entire_batch_then_staggers_single_tasks(monkeypatch):
    celery = _FakeCelery()
    redis_client = Mock()
    redis_client.eval.return_value = 1
    events = []
    redis_client.set.side_effect = lambda key, value, **kwargs: events.append(("reserve", key, value, kwargs)) or True
    single_task = Mock()
    single_task.apply_async.side_effect = lambda **kwargs: events.append(("enqueue", kwargs))
    monkeypatch.setattr(rejudge_dispatch, "clear_submission_lock", lambda sid: events.append(("clear", sid)))
    monkeypatch.setattr(rejudge_dispatch, "supersede_latest_attempt", lambda sid: events.append(("supersede", sid)))
    monkeypatch.setattr(rejudge_dispatch, "reset_submission_for_rejudge", lambda sid, problem_type: events.append(("reset", sid, problem_type)))
    task = rejudge_tasks.register_bulk_rejudge_task(celery, redis_client, single_task)

    task([
        {"id": 11, "problem_type": 1, "status": "Running"},
        {"id": 12, "problem_type": 2, "status": "Unaccepted"},
    ], "rejudge:batch:example")

    assert events == [
        ("reserve", "submission:11:pending_requeue", "rejudge:batch:example", {"ex": 602}),
        ("reserve", "submission:12:pending_requeue", "rejudge:batch:example", {"ex": 603}),
        ("clear", 11),
        ("reset", 11, 1),
        ("supersede", 12),
        ("reset", 12, 2),
        ("enqueue", {"args": [11, "rejudge:batch:example"], "countdown": 0, "queue": "celery"}),
        ("enqueue", {"args": [12, "rejudge:batch:example"], "countdown": 1, "queue": "celery"}),
    ]
    assert redis_client.hset.call_args_list == [
        call("rejudge:batch:example", mapping={"scheduled": 1}),
        call("rejudge:batch:example", mapping={"scheduled": 2}),
        call("rejudge:batch:example", mapping={"dispatch_status": "dispatched"}),
    ]


def test_bulk_rejudge_duplicate_delivery_cannot_reset_again(monkeypatch):
    celery = _FakeCelery()
    redis_client = Mock()
    redis_client.eval.side_effect = [1, 0]
    dispatch = Mock()
    monkeypatch.setattr(rejudge_tasks, "dispatch_rejudge_submissions", dispatch)
    single_task = Mock()
    task = rejudge_tasks.register_bulk_rejudge_task(celery, redis_client, single_task)
    rows = [{"id": 11, "problem_type": 1, "status": "Accepted"}]

    task(rows, "rejudge:batch:example")
    task(rows, "rejudge:batch:example")

    dispatch.assert_called_once_with(rows, "rejudge:batch:example", single_task, redis_client)
    assert "'queued'" in redis_client.eval.call_args[0][0]
    assert "'dispatching'" in redis_client.eval.call_args[0][0]


def test_bulk_rejudge_partial_failure_marks_failed_and_never_retries(monkeypatch):
    celery = _FakeCelery()
    redis_client = Mock()
    redis_client.eval.return_value = 1
    dispatch = Mock(side_effect=RuntimeError("submission reset failed"))
    monkeypatch.setattr(rejudge_tasks, "dispatch_rejudge_submissions", dispatch)
    task = rejudge_tasks.register_bulk_rejudge_task(celery, redis_client, Mock())

    with pytest.raises(RuntimeError, match="submission reset failed"):
        task([{"id": 11}], "rejudge:batch:example")

    redis_client.hset.assert_called_once_with("rejudge:batch:example", mapping={"dispatch_status": "failed", "error": "submission reset failed"})


def test_bulk_rejudge_reservation_failure_happens_before_any_reset(monkeypatch):
    redis_client = Mock()
    redis_client.set.return_value = False
    reset = Mock()
    monkeypatch.setattr(rejudge_dispatch, "reset_submission_for_rejudge", reset)
    single_task = Mock()

    with pytest.raises(RuntimeError, match="重测预约写入失败"):
        rejudge_dispatch.dispatch_rejudge_submissions([{"id": 11}], "batch", single_task, redis_client)

    reset.assert_not_called()
    single_task.apply_async.assert_not_called()
