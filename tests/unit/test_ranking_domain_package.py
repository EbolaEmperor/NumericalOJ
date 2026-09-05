"""打榜赛领域包的 canonical 路径与分层契约。"""

import ast
import inspect
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RANKING_ROOT = ROOT / "backend" / "oj_modules" / "ranking"


def test_ranking_package_initializers_are_explicit_and_lightweight():
    paths = [
        RANKING_ROOT / "__init__.py",
        RANKING_ROOT / "agent_judge" / "__init__.py",
        RANKING_ROOT / "reverse_judge" / "__init__.py",
    ]
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        assert not any(
            isinstance(node, (ast.Import, ast.ImportFrom))
            for node in tree.body
        )
        assignments = [
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "__all__"
                for target in node.targets
            )
        ]
        assert len(assignments) == 1
        assert isinstance(assignments[0].value, (ast.List, ast.Tuple))


def test_reverse_judge_modules_follow_one_way_responsibility_dependencies():
    imports_by_file = {}
    for name in ("db.py", "traces.py", "service.py"):
        tree = ast.parse(
            (RANKING_ROOT / "reverse_judge" / name).read_text(encoding="utf-8")
        )
        imports_by_file[name] = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }

    assert not any(
        module.startswith("backend.oj_modules.ranking.reverse_judge")
        for module in imports_by_file["db.py"]
    )
    assert not any(
        module.startswith("backend.oj_modules.ranking.reverse_judge")
        for module in imports_by_file["traces.py"]
    )
    assert {
        "backend.oj_modules.ranking.reverse_judge.db",
        "backend.oj_modules.agents.sessions",
    }.issubset(imports_by_file["service.py"])
    assert "backend.oj_modules.ranking.reverse_judge.traces" not in imports_by_file["service.py"]


def test_ranking_http_adapters_do_not_import_each_other_or_task_implementations():
    api_tree = ast.parse(
        (ROOT / "backend" / "oj_modules" / "api" / "ranking_api.py").read_text(
            encoding="utf-8"
        )
    )
    route_tree = ast.parse(
        (ROOT / "backend" / "oj_modules" / "routes" / "ranking_routes.py").read_text(
            encoding="utf-8"
        )
    )

    def imported_modules(tree):
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module)
            elif isinstance(node, ast.Import):
                modules.update(alias.name for alias in node.names)
        return modules

    assert not any(
        module.startswith("backend.oj_modules.routes")
        for module in imported_modules(api_tree)
    )
    assert not any(
        module.startswith("backend.oj_modules.tasks")
        for module in imported_modules(route_tree)
    )


def test_shared_ranking_helpers_preserve_format_and_validation_contracts():
    from datetime import datetime

    from backend.oj_modules.ranking import artifacts, batch, presentation

    assert presentation.normalize_answer_format(" ZIP ") == "zip"
    assert presentation.normalize_answer_format("invalid") == "json"
    assert presentation.competition_scoring_mode({"scoring_mode": "ELO"}) == "elo"
    assert presentation.page_window(5, 12, radius=2) == [3, 4, 5, 6, 7]
    assert presentation.submission_quota_message({
        "limit": 3,
        "next_reset": datetime(2026, 8, 2, 9, 7),
    }) == "本轮提交次数已用完（每 48 小时上限 3 次），将于 2026-08-02 09:07 刷新。"

    assert batch.build_repo_url("git@example/<username>.git", "alice") == (
        "git@example/alice.git"
    )
    assert batch.USERNAME_RE.fullmatch("alice-01")
    assert not batch.USERNAME_RE.fullmatch("-alice")
    assert artifacts.attachment_media_kind("plot.PNG") == "image"
    assert artifacts.attachment_media_kind("demo.webm") == "video"
    assert artifacts.attachment_media_kind("unsafe.svg") is None


def test_init_ranking_module_keeps_old_positionals_and_injects_runtime_ports(
        monkeypatch):
    from backend.oj_modules.routes import ranking_routes

    positional = [object() for _ in range(8)]
    runtime_ports = [lambda *_args: index for index in range(8)]
    monkeypatch.setattr(ranking_routes, "init_match_cache", lambda _redis: None)
    for name in (
        "build_current_judge_snapshot",
        "get_judge_progress_snapshot",
        "subscribe_judge_run_events",
        "get_reverse_judge_progress_snapshot",
        "subscribe_reverse_judge_events",
        "get_probe_job",
        "get_bulk_rejudge_job",
        "save_bulk_rejudge_job",
    ):
        monkeypatch.setattr(ranking_routes, name, None)

    ranking_routes.init_ranking_module(
        *positional,
        judge_progress_reader=runtime_ports[0],
        judge_event_subscriber=runtime_ports[1],
        current_judge_snapshot_builder=runtime_ports[2],
        reverse_progress_reader=runtime_ports[3],
        reverse_event_subscriber=runtime_ports[4],
        batch_job_reader=runtime_ports[5],
        bulk_job_reader=runtime_ports[6],
        bulk_job_writer=runtime_ports[7],
    )

    assert ranking_routes._evaluate_ranking_task is positional[0]
    assert ranking_routes._bulk_rejudge_task is positional[7]
    assert ranking_routes.get_judge_progress_snapshot is runtime_ports[0]
    assert ranking_routes.subscribe_judge_run_events is runtime_ports[1]
    assert ranking_routes.build_current_judge_snapshot is runtime_ports[2]
    assert ranking_routes.get_reverse_judge_progress_snapshot is runtime_ports[3]
    assert ranking_routes.subscribe_reverse_judge_events is runtime_ports[4]
    assert ranking_routes.get_probe_job is runtime_ports[5]
    assert ranking_routes.get_bulk_rejudge_job is runtime_ports[6]
    assert ranking_routes.save_bulk_rejudge_job is runtime_ports[7]

    parameters = list(inspect.signature(ranking_routes.init_ranking_module).parameters)
    assert parameters[:8] == [
        "evaluate_ranking_task",
        "elo_initial_burst_task",
        "agent_judge_task",
        "reverse_judge_task",
        "redis_client",
        "batch_probe_task",
        "batch_run_task",
        "bulk_rejudge_task",
    ]
