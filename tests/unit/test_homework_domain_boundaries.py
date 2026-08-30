import ast
from pathlib import Path

from backend.oj_modules.homework import progress, records, runtime, targets
from backend.oj_modules.routes import homework_routes


ROOT = Path(__file__).resolve().parents[2]


def test_homework_api_task_and_domain_do_not_import_routes():
    relative_paths = (
        "backend/oj_modules/api/homework_api.py",
        "backend/oj_modules/tasks/homework_admin_tasks.py",
        "backend/oj_modules/homework/plagiarism.py",
        "backend/oj_modules/homework/progress.py",
        "backend/oj_modules/homework/records.py",
        "backend/oj_modules/homework/repository.py",
        "backend/oj_modules/homework/runtime.py",
        "backend/oj_modules/homework/targets.py",
    )

    for relative_path in relative_paths:
        tree = ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))
        imported_modules = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        imported_modules.update(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        )

        assert not any(
            module == "backend.oj_modules.routes"
            or module.startswith("backend.oj_modules.routes.")
            for module in imported_modules
        ), relative_path


def test_homework_route_uses_canonical_adapter_dependencies():
    assert (
        homework_routes.parse_plagiarism_mark_payload
        is targets.parse_plagiarism_mark_payload
    )
    assert (
        homework_routes._load_plagiarism_records_for_class
        is records._load_plagiarism_records_for_class
    )
    assert (
        homework_routes.get_plagiarism_progress_payload
        is runtime.get_plagiarism_progress_payload
    )


def test_plagiarism_csv_is_a_flask_independent_artifact(monkeypatch):
    monkeypatch.setattr(
        records,
        "_load_plagiarism_records_for_class",
        lambda _class_en: [
            {
                "id": 1,
                "user_id": 2,
                "username": "alice",
                "class_cn": "一班",
                "problem_id": 3,
                "problem_title": "测试题",
                "submission_id": 4,
                "comparison_rule": "byte-identical",
                "matched_usernames_text": "bob",
                "created_at": "2026-08-02 12:00:00",
            }
        ],
    )

    artifact = records.build_plagiarism_records_csv("C1")

    assert artifact.filename == "C1_plagiarism_records.csv"
    assert artifact.content_type == "text/csv; charset=GBK"
    csv_text = artifact.content.decode("gbk")
    assert "用户名" in csv_text
    assert "alice" in csv_text
    assert "测试题" in csv_text


def test_plagiarism_payload_is_resolved_inside_the_domain(monkeypatch):
    monkeypatch.setattr(
        targets,
        "get_class_by_en",
        lambda class_en: {"class_en": class_en, "class_cn": "一班"},
    )
    monkeypatch.setattr(
        targets,
        "_get_class_homework_target_map",
        lambda _class_en: {
            "problem:7": {
                "kind": "problem",
                "id": 7,
                "key": "problem:7",
                "title": "测试题",
            }
        },
    )

    payload = targets.parse_plagiarism_mark_payload({
        "class_en": "C1",
        "mode": "threshold",
        "threshold": 90,
        "targets": ["problem:7", "problem:7"],
    })

    assert payload["class_cn"] == "一班"
    assert payload["threshold"] == 0.9
    assert payload["problem_ids"] == [7]
    assert payload["targets"] == [{
        "kind": "problem",
        "id": 7,
        "key": "problem:7",
        "title": "测试题",
    }]


def test_progress_payload_round_trip_preserves_existing_contract():
    class FakeRedis:
        def __init__(self):
            self.values = {}

        def setex(self, key, _ttl, value):
            self.values[key] = value

        def get(self, key):
            return self.values.get(key)

    redis_client = FakeRedis()
    progress.update_plagiarism_progress(
        redis_client,
        "task-1",
        "checking",
        1,
        4,
        "比较中",
        result={"group_count": 2},
    )

    assert progress.get_plagiarism_progress_payload(
        redis_client,
        "task-1",
    ) == {
        "stage": "checking",
        "current": 1,
        "total": 4,
        "message": "比较中",
        "percentage": 25,
        "result": {"group_count": 2},
    }


def test_homework_runtime_wires_tasks_zip_and_cache_invalidator():
    class FakeAsyncResult:
        def __init__(self, task_id):
            self.id = task_id

    class FakeTask:
        def __init__(self, task_id):
            self.task_id = task_id
            self.calls = []

        def delay(self, *args):
            self.calls.append(args)
            return FakeAsyncResult(self.task_id)

    class FakeBinaryRedis:
        def get(self, key):
            return {"export_zip:zip-task": b"zip-bytes"}.get(key)

    export_task = FakeTask("export-1")
    plagiarism_task = FakeTask("plagiarism-1")
    invalidated = []
    previous = (
        runtime._text_redis_client,
        runtime._binary_redis_client,
        runtime._export_task,
        runtime._plagiarism_task,
        runtime._problem_list_cache_invalidator,
    )
    try:
        runtime.configure_homework_runtime(
            None,
            FakeBinaryRedis(),
            export_task,
            plagiarism_task,
            problem_list_cache_invalidator=invalidated.append,
        )

        assert runtime.start_export_codes_task("C1") == "export-1"
        assert export_task.calls == [("C1",)]
        assert runtime.start_plagiarism_mark_task(
            "C1",
            "threshold",
            0.9,
            [{"kind": "problem", "id": 7}],
        ) == "plagiarism-1"
        assert plagiarism_task.calls == [(
            "C1",
            "threshold",
            0.9,
            [{"kind": "problem", "id": 7}],
        )]
        assert runtime.get_export_zip("zip-task") == b"zip-bytes"

        runtime.invalidate_problem_list_cache_for_class("C1")
        assert invalidated == ["C1"]
    finally:
        runtime.configure_homework_runtime(
            previous[0],
            previous[1],
            previous[2],
            previous[3],
            problem_list_cache_invalidator=previous[4],
        )
