def test_pending_watchdog_registration_keeps_wire_name_and_is_idempotent():
    from backend.oj_modules.runtime import pending_recovery

    class FakeCelery:
        def __init__(self):
            self.tasks = {}

        def task(self, *, name, bind):
            assert bind is True

            def decorator(function):
                self.tasks[name] = function
                return function

            return decorator

    celery = FakeCelery()
    dependencies = [object() for _ in range(8)]
    first = pending_recovery.register_pending_requeue_watchdog_task(
        celery,
        dependencies[0],
        dependencies[1],
        promptly_task=dependencies[2],
        ranking_task=dependencies[3],
        elo_initial_burst_task=dependencies[4],
        agent_judge_task=dependencies[5],
        reverse_judge_task=dependencies[6],
    )
    second = pending_recovery.register_pending_requeue_watchdog_task(
        celery,
        dependencies[0],
        dependencies[1],
    )

    assert pending_recovery.PENDING_REQUEUE_WATCHDOG_TASK_NAME == (
        "oj.pending_requeue_watchdog"
    )
    assert first is second
    assert celery.tasks == {"oj.pending_requeue_watchdog": first}
