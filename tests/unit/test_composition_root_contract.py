"""组合根的运行期注入与 Celery 拓扑契约。"""

import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap


ROOT = Path(__file__).resolve().parents[2]
RESULT_PREFIX = "NUMOJ_COMPOSITION_ROOT_RESULT="

EXPECTED_TASK_QUEUES = {
    "oj.agent.generate_testdata": "agent",
    "oj.agent.solve_problem": "agent",
    "oj.ai_detection.detect_batch": "celery",
    "oj.ai_detection.detect_filtered": "celery",
    "oj.ai_detection.detect_single": "celery",
    "oj.ai_detection.detect_user": "celery",
    "oj.evaluate_ranking_submission": "celery",
    "oj.evaluate_submission": "celery",
    "oj.homework.export_codes_with_plagiarism_check_task": "celery",
    "oj.homework.mark_plagiarism_task": "celery",
    "oj.pending_requeue_watchdog": "celery",
    "oj.promptly.generate_submission": "agent",
    "oj.ranking_agent_judge": "judge",
    "oj.ranking_agent_judge_paused_probe": "judge",
    "oj.ranking_batch_probe": "celery",
    "oj.ranking_batch_run": "celery",
    "oj.ranking_bulk_rejudge": "celery",
    "oj.ranking_elo_initial_burst": "celery",
    "oj.ranking_elo_match": "celery",
    "oj.ranking_elo_matchmaker_tick": "celery",
    "oj.ranking_reverse_judge": "judge",
    "oj.rejudge.evaluate_submission_and_update": "celery",
    "oj.repository.build_index": "celery",
    "oj.transcribe_written_homework_to_latex": "celery",
}


def _imported_modules(relative_path):
    tree = ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))
    modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    modules.update(
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    )
    return modules


def test_rejudge_route_does_not_import_task_adapters():
    imported_modules = _imported_modules("oj_modules/routes/rejudge_routes.py")

    assert not any(
        module == "oj_modules.tasks" or module.startswith("oj_modules.tasks.")
        for module in imported_modules
    )


def test_composition_root_uses_canonical_task_registry():
    imported_modules = _imported_modules("oj.py")

    assert "oj_modules.tasks.registry" in imported_modules
    assert "oj_modules.tasks" not in imported_modules


def test_real_oj_import_preserves_runtime_ports_and_task_topology():
    script = textwrap.dedent(
        f"""
        import inspect
        import json

        import config
        from oj_modules import db_services
        from oj_modules.infrastructure import mysql as mysql_infrastructure
        from oj_modules.infrastructure import redis as redis_infrastructure
        from oj_modules.runtime import pending_recovery
        from oj_modules.tasks import registry as task_registry


        class NoIORedisClient:
            def __init__(self, label):
                self.label = label

            def __getattr__(self, name):
                raise AssertionError(
                    f"真实 import oj 不应执行 Redis 命令：{{self.label}}.{{name}}"
                )


        text_redis = NoIORedisClient("text")
        binary_redis = NoIORedisClient("binary")
        blocking_redis = NoIORedisClient("blocking")
        redis_infrastructure.create_text_redis_client = lambda: text_redis
        redis_infrastructure.create_binary_redis_client = lambda: binary_redis
        redis_infrastructure.create_blocking_redis_client = lambda: blocking_redis

        def forbid_database_access(*_args, **_kwargs):
            raise AssertionError("真实 import oj 不应连接或写入数据库")

        db_services.get_db_connection = forbid_database_access
        mysql_infrastructure.get_db_connection = forbid_database_access
        config.SECRET_KEY = "composition-root-unit-test"

        def forbid_scheduler(name):
            def forbidden(*_args, **_kwargs):
                raise AssertionError(f"真实 import oj 不应运行调度或恢复入口：{{name}}")
            return forbidden

        task_registry.seed_elo_matchmaker_tick = forbid_scheduler(
            "seed_elo_matchmaker_tick"
        )
        task_registry.seed_agent_judge_paused_probe = forbid_scheduler(
            "seed_agent_judge_paused_probe"
        )
        pending_recovery.seed_pending_requeue_watchdog = forbid_scheduler(
            "seed_pending_requeue_watchdog"
        )
        pending_recovery.requeue_pending_on_startup = forbid_scheduler(
            "requeue_pending_on_startup"
        )

        import oj
        from oj_modules.homework import runtime as homework_runtime
        from oj_modules.judging import core as judging_core
        from oj_modules.problems import catalog as problem_catalog
        from oj_modules.routes import ranking_routes, rejudge_routes, submission_routes
        from oj_modules.tasks import evaluate_tasks

        assert homework_runtime._text_redis_client is oj.rds is text_redis
        assert homework_runtime._binary_redis_client is oj.rds_binary is binary_redis
        assert (
            homework_runtime._export_task
            is oj.export_codes_with_plagiarism_check
        )
        assert homework_runtime._plagiarism_task is oj.mark_homework_plagiarism
        assert (
            homework_runtime._problem_list_cache_invalidator
            is problem_catalog.invalidate_problem_list_cache_for_class
        )

        assert rejudge_routes._rds is oj.rds
        assert rejudge_routes._rejudge_task is oj.rejudge_submission_and_update

        ranking_runtime_ports = (
            "build_current_judge_snapshot",
            "get_judge_progress_snapshot",
            "subscribe_judge_run_events",
            "get_reverse_judge_progress_snapshot",
            "subscribe_reverse_judge_events",
            "get_probe_job",
            "get_bulk_rejudge_job",
            "save_bulk_rejudge_job",
        )
        for name in ranking_runtime_ports:
            assert getattr(ranking_routes, name) is getattr(task_registry, name), name

        assert evaluate_tasks.core is judging_core
        assert submission_routes.judger_core is judging_core
        unwrapped_evaluate = inspect.unwrap(oj.evaluate_submission.run)
        assert unwrapped_evaluate.__globals__["core"] is judging_core

        task_names = sorted(
            name for name in oj.celery.tasks if name.startswith("oj.")
        )
        task_queues = {{}}
        for name in task_names:
            task = oj.celery.tasks[name]
            assert task.name == name
            route = oj.celery.amqp.router.route({{}}, name)
            queue = route["queue"]
            task_queues[name] = getattr(queue, "name", str(queue))

        print(
            {RESULT_PREFIX!r}
            + json.dumps(
                {{"task_names": task_names, "task_queues": task_queues}},
                sort_keys=True,
            )
        )
        """
    )
    env = os.environ.copy()
    env.update(
        PYTHONDONTWRITEBYTECODE="1",
        NUMOJ_SERVICE_NAME="unit-composition-root",
        SECRET_KEY="composition-root-unit-test",
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, (
        "真实 import oj 的组合根断言失败\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
    payload_line = next(
        (
            line
            for line in result.stdout.splitlines()
            if line.startswith(RESULT_PREFIX)
        ),
        None,
    )
    assert payload_line is not None, result.stdout
    payload = json.loads(payload_line.removeprefix(RESULT_PREFIX))

    assert payload["task_names"] == sorted(EXPECTED_TASK_QUEUES)
    assert payload["task_queues"] == EXPECTED_TASK_QUEUES
