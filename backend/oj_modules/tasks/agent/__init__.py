"""Agent Celery 适配层；注册入口由 :mod:`backend.oj_modules.tasks.agent.registry` 聚合。"""

from importlib import import_module


__all__ = [
    "AGENT_GENERATE_TESTDATA_TASK_NAME",
    "AGENT_QUEUE_DISPATCH_TASK_NAME",
    "AGENT_QUEUE_RECOVERY_TASK_NAME",
    "AGENT_RUN_TURN_TASK_NAME",
    "AGENT_SOLVE_TASK_NAME",
    "apply_agent_concurrency_limit",
    "build_agent_run_terminator",
    "get_agent_run_snapshot",
    "init_agent_progress_cache",
    "init_agent_queue_dispatcher",
    "install_agent_concurrency_control",
    "register_agent_generate_testdata_task",
    "register_agent_run_turn_task",
    "register_agent_queue_tasks",
    "register_agent_solve_problem_task",
    "subscribe_agent_billing_events",
    "subscribe_agent_run_events",
]

_REGISTRY_EXPORTS = {
    "AGENT_GENERATE_TESTDATA_TASK_NAME": "AGENT_GENERATE_TESTDATA_TASK_NAME",
    "AGENT_QUEUE_DISPATCH_TASK_NAME": "AGENT_QUEUE_DISPATCH_TASK_NAME",
    "AGENT_QUEUE_RECOVERY_TASK_NAME": "AGENT_QUEUE_RECOVERY_TASK_NAME",
    "AGENT_RUN_TURN_TASK_NAME": "AGENT_RUN_TURN_TASK_NAME",
    "AGENT_SOLVE_TASK_NAME": "AGENT_SOLVE_TASK_NAME",
    "apply_agent_concurrency_limit": "apply_agent_concurrency_limit",
    "build_agent_run_terminator": "build_agent_run_terminator",
    "get_agent_run_snapshot": "get_agent_run_snapshot",
    "init_agent_progress_cache": "init_agent_progress_cache",
    "init_agent_queue_dispatcher": "init_agent_queue_dispatcher",
    "install_agent_concurrency_control": "install_agent_concurrency_control",
    "register_agent_generate_testdata_task": "register_agent_generate_testdata_task",
    "register_agent_run_turn_task": "register_agent_run_turn_task",
    "register_agent_queue_tasks": "register_agent_queue_tasks",
    "register_agent_solve_problem_task": "register_agent_solve_problem_task",
    "subscribe_agent_billing_events": "subscribe_agent_billing_events",
    "subscribe_agent_run_events": "subscribe_agent_run_events",
}


def __getattr__(name):
    if name not in _REGISTRY_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(
        import_module("backend.oj_modules.tasks.agent.registry"),
        _REGISTRY_EXPORTS[name],
    )
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(_REGISTRY_EXPORTS))
