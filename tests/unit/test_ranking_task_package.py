import ast
import importlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TASKS_ROOT = ROOT / "backend" / "oj_modules" / "tasks"

EXPECTED_TASK_NAMES = {
    "ranking.evaluate": {
        "RANKING_EVALUATE_TASK_NAME": "oj.evaluate_ranking_submission",
    },
    "ranking.elo": {
        "ELO_MATCH_TASK_NAME": "oj.ranking_elo_match",
        "ELO_INITIAL_BURST_TASK_NAME": "oj.ranking_elo_initial_burst",
        "ELO_MATCHMAKER_TICK_TASK_NAME": "oj.ranking_elo_matchmaker_tick",
    },
    "ranking.agent_judge": {
        "RANKING_AGENT_JUDGE_TASK_NAME": "oj.ranking_agent_judge",
        "RANKING_AGENT_JUDGE_PAUSED_PROBE_TASK_NAME": (
            "oj.ranking_agent_judge_paused_probe"
        ),
    },
    "ranking.reverse_judge": {
        "RANKING_REVERSE_JUDGE_TASK_NAME": "oj.ranking_reverse_judge",
    },
    "ranking.batch_pull": {
        "PROBE_TASK_NAME": "oj.ranking_batch_probe",
        "RUN_TASK_NAME": "oj.ranking_batch_run",
    },
    "ranking.bulk_rejudge": {
        "TASK_NAME": "oj.ranking_bulk_rejudge",
    },
}


def test_ranking_task_names_remain_wire_compatible():
    for module_name, expected in EXPECTED_TASK_NAMES.items():
        module = importlib.import_module(f"backend.oj_modules.tasks.{module_name}")
        assert {name: getattr(module, name) for name in expected} == expected


def test_ranking_task_package_initializer_is_explicit_and_lightweight():
    path = TASKS_ROOT / "ranking" / "__init__.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    assert not any(
        isinstance(node, (ast.Import, ast.ImportFrom))
        for node in tree.body
    )
    all_assignments = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__all__"
            for target in node.targets
        )
    ]
    assert len(all_assignments) == 1
    assert isinstance(all_assignments[0].value, (ast.List, ast.Tuple))
