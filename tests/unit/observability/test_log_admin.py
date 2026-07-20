from __future__ import annotations

import fcntl
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from scripts import log_admin


def _args(**overrides):
    values = {
        "dataset": None,
        "request_id": None,
        "submission_id": None,
        "task_id": None,
        "limit": 100,
        "lines": 100,
        "max_errors": 20,
        "json": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _schema_event(**fields):
    return {
        "schema": {
            "name": log_admin.SCHEMA_NAME,
            "version": log_admin.SCHEMA_VERSION,
        },
        **fields,
    }


def _install_dataset(monkeypatch, root: Path, relative: str = "audit/auth.jsonl"):
    monkeypatch.setattr(log_admin, "LOG_ROOT", root)
    monkeypatch.setattr(
        log_admin,
        "DATASET_PATHS",
        {"numoj.audit.auth": relative},
    )


def test_dataset_path_normalizes_short_name_and_accepts_full_name(
    monkeypatch, tmp_path
):
    _install_dataset(monkeypatch, tmp_path / "logs")

    expected = tmp_path / "logs" / "audit/auth.jsonl"
    assert log_admin._dataset_path(" audit.auth ") == expected
    assert log_admin._dataset_path("numoj.audit.auth") == expected


def test_dataset_path_rejects_unknown_name_with_sorted_choices(monkeypatch, tmp_path):
    monkeypatch.setattr(log_admin, "LOG_ROOT", tmp_path)
    monkeypatch.setattr(
        log_admin,
        "DATASET_PATHS",
        {
            "numoj.runtime.application": "runtime/application.jsonl",
            "numoj.audit.auth": "audit/auth.jsonl",
        },
    )

    with pytest.raises(ValueError) as error:
        log_admin._dataset_path("missing")

    message = str(error.value)
    assert "未知 dataset 'missing'" in message
    assert "numoj.audit.auth, numoj.runtime.application" in message


def test_rotated_files_orders_numeric_backups_then_active_and_ignores_unsafe(
    tmp_path,
):
    active = tmp_path / "events.jsonl"
    active.write_text("active", encoding="utf-8")
    oldest = tmp_path / "events.jsonl.10"
    oldest.write_text("oldest", encoding="utf-8")
    older = tmp_path / "events.jsonl.3"
    older.write_text("older", encoding="utf-8")
    (tmp_path / "events.jsonl.invalid").write_text("ignored", encoding="utf-8")
    (tmp_path / "events.jsonl.2").mkdir()
    target = tmp_path / "target"
    target.write_text("target", encoding="utf-8")
    (tmp_path / "events.jsonl.1").symlink_to(target)

    assert log_admin._rotated_files(active) == [oldest, older, active]


def test_rotated_files_omits_symlinked_active_file(tmp_path):
    target = tmp_path / "target.jsonl"
    target.write_text("secret", encoding="utf-8")
    active = tmp_path / "events.jsonl"
    active.symlink_to(target)
    backup = tmp_path / "events.jsonl.1"
    backup.write_text("safe", encoding="utf-8")

    assert log_admin._rotated_files(active) == [backup]


def test_iter_lines_reads_rotations_oldest_first_and_replaces_bad_utf8(
    monkeypatch, tmp_path
):
    root = tmp_path / "logs"
    _install_dataset(monkeypatch, root)
    active = root / "audit/auth.jsonl"
    active.parent.mkdir(parents=True)
    (active.parent / "auth.jsonl.2").write_text("oldest\n", encoding="utf-8")
    (active.parent / "auth.jsonl.1").write_bytes(b"newer-\xff\n")
    active.write_text("active\n", encoding="utf-8")

    assert list(log_admin._iter_lines("audit.auth")) == [
        "oldest\n",
        "newer-�\n",
        "active\n",
    ]


def test_last_lines_reads_from_tail_without_scanning_whole_file():
    content = (b"old\n" * 100_000) + b"tail-a\ntail-b\n"

    class TrackingStream(io.BytesIO):
        bytes_read = 0

        def read(self, size=-1):
            data = super().read(size)
            self.bytes_read += len(data)
            return data

    stream = TrackingStream(content)
    path = MagicMock()
    path.open.return_value.__enter__.return_value = stream

    assert log_admin._last_lines(path, 2) == ["tail-a", "tail-b"]
    assert stream.bytes_read <= 64 * 1024


def test_nested_returns_value_and_none_for_missing_or_non_mapping_nodes():
    payload = {"request": {"id": "request-1", "broken": "text"}}

    assert log_admin._nested(payload, "request", "id") == "request-1"
    assert log_admin._nested(payload, "request", "missing") is None
    assert log_admin._nested(payload, "request", "broken", "id") is None
    assert log_admin._nested("not-a-dict", "request") is None


@pytest.mark.parametrize(
    ("field", "payload", "expected"),
    [
        ("request_id", {"request": {"id": "r-1"}}, "r-1"),
        ("request_id", {"trace": {"id": "trace-1"}}, "trace-1"),
        ("request_id", {"labels": {"request_id": 12}}, "12"),
        ("submission_id", {"submission": {"id": 23}}, "23"),
        ("submission_id", {"labels": {"submission_id": "s-2"}}, "s-2"),
        ("task_id", {"task": {"id": "task-1"}}, "task-1"),
        ("task_id", {"labels": {"task_id": 34}}, "34"),
    ],
)
def test_matches_supports_primary_and_label_correlation_fields(
    field, payload, expected
):
    assert log_admin._matches(payload, field, expected) is True


def test_matches_returns_false_for_missing_or_different_id():
    assert log_admin._matches({"request": {"id": "one"}}, "request_id", "two") is False
    assert log_admin._matches({}, "submission_id", "1") is False


def test_matches_rejects_unsupported_field():
    with pytest.raises(KeyError):
        log_admin._matches({}, "unknown", "1")


def test_build_parser_binds_all_subcommands_and_defaults():
    parser = log_admin.build_parser()

    cases = {
        "init": log_admin.command_init,
        "serve": log_admin.command_serve,
        "list": log_admin.command_list,
        "status": log_admin.command_status,
        "tail": log_admin.command_tail,
        "find": log_admin.command_find,
        "validate": log_admin.command_validate,
        "doctor": log_admin.command_doctor,
    }
    for command, handler in cases.items():
        suffix = ["audit.auth"] if command == "tail" else []
        parsed = parser.parse_args([command, *suffix])
        assert parsed.command == command
        assert parsed.handler is handler

    serve = parser.parse_args(["serve"])
    assert serve.max_bytes == log_admin.DEFAULT_MAX_BYTES
    assert serve.backups == log_admin.DEFAULT_BACKUPS
    assert serve.no_journal is False
    assert parser.parse_args(["status"]).json is False
    assert parser.parse_args(["tail", "audit.auth"]).lines == 100
    assert parser.parse_args(["find", "--request-id", "r"]).limit == 100
    assert parser.parse_args(["validate"]).max_errors == 20


def test_build_parser_parses_explicit_cli_options():
    parser = log_admin.build_parser()

    serve = parser.parse_args(
        ["serve", "--max-bytes", "4096", "--backups", "3", "--no-journal"]
    )
    assert (serve.max_bytes, serve.backups, serve.no_journal) == (4096, 3, True)
    assert parser.parse_args(["status", "--json"]).json is True

    tail = parser.parse_args(["tail", "task.lifecycle", "--lines", "7"])
    assert (tail.dataset, tail.lines) == ("task.lifecycle", 7)

    find = parser.parse_args(
        [
            "find",
            "--submission-id",
            "42",
            "--dataset",
            "audit.submissions",
            "--limit",
            "2",
        ]
    )
    assert (find.submission_id, find.dataset, find.limit) == (
        "42",
        "audit.submissions",
        2,
    )
    validate = parser.parse_args(
        ["validate", "--dataset", "access.http", "--max-errors", "4"]
    )
    assert (validate.dataset, validate.max_errors) == ("access.http", 4)


def test_build_parser_requires_a_subcommand():
    with pytest.raises(SystemExit) as error:
        log_admin.build_parser().parse_args([])
    assert error.value.code == 2


def test_command_init_initializes_fixed_root_and_prints_it(monkeypatch, tmp_path, capsys):
    root = tmp_path / "logs"
    initializer = MagicMock(return_value=root)
    monkeypatch.setattr(log_admin, "LOG_ROOT", root)
    monkeypatch.setattr(log_admin, "init_log_tree", initializer)

    assert log_admin.command_init(_args()) == 0
    initializer.assert_called_once_with(root)
    assert capsys.readouterr().out == f"{root}\n"


def test_command_serve_forwards_rotation_and_journal_options(monkeypatch, tmp_path):
    root = tmp_path / "logs"
    server = MagicMock()
    monkeypatch.setattr(log_admin, "LOG_ROOT", root)
    monkeypatch.setattr(log_admin, "serve_collector", server)

    args = _args(max_bytes=2048, backups=4, no_journal=True)
    assert log_admin.command_serve(args) == 0
    server.assert_called_once_with(
        root=root,
        max_bytes=2048,
        backups=4,
        collect_journal=False,
    )


def test_command_list_prints_datasets_in_sorted_order(monkeypatch, capsys):
    monkeypatch.setattr(
        log_admin,
        "DATASET_PATHS",
        {
            "numoj.runtime.application": "runtime/application.jsonl",
            "numoj.audit.auth": "audit/auth.jsonl",
        },
    )

    assert log_admin.command_list(_args()) == 0
    assert capsys.readouterr().out.splitlines() == [
        "numoj.audit.auth\taudit/auth.jsonl",
        "numoj.runtime.application\truntime/application.jsonl",
    ]


def test_command_status_json_reports_size_time_and_rotation_count(
    monkeypatch, tmp_path, capsys
):
    root = tmp_path / "logs"
    _install_dataset(monkeypatch, root)
    active = root / "audit/auth.jsonl"
    active.parent.mkdir(parents=True)
    active.write_text("active", encoding="utf-8")
    (active.parent / "auth.jsonl.2").write_text("old", encoding="utf-8")
    (active.parent / "auth.jsonl.1").write_text("new", encoding="utf-8")
    os.utime(active, (1_700_000_000, 1_700_000_000))

    assert log_admin.command_status(_args(json=True)) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows == [
        {
            "bytes": 6,
            "dataset": "numoj.audit.auth",
            "exists": True,
            "path": str(active),
            "rotated_files": 2,
            "updated_at": "2023-11-14T22:13:20+00:00",
        }
    ]


def test_command_status_text_reports_missing_active_and_existing_rotation(
    monkeypatch, tmp_path, capsys
):
    root = tmp_path / "logs"
    _install_dataset(monkeypatch, root)
    backup = root / "audit/auth.jsonl.1"
    backup.parent.mkdir(parents=True)
    backup.write_text("old", encoding="utf-8")

    assert log_admin.command_status(_args(json=False)) == 0
    line = capsys.readouterr().out
    assert "numoj.audit.auth" in line
    assert "0 bytes" in line
    assert "rotated=1" in line
    assert str(root / "audit/auth.jsonl") in line


def test_command_status_rejects_symlinked_active_file(monkeypatch, tmp_path):
    root = tmp_path / "logs"
    _install_dataset(monkeypatch, root)
    active = root / "audit/auth.jsonl"
    active.parent.mkdir(parents=True)
    target = tmp_path / "outside.jsonl"
    target.write_text("sensitive", encoding="utf-8")
    active.symlink_to(target)

    with pytest.raises(RuntimeError, match="不能包含符号链接"):
        log_admin.command_status(_args(json=True))

    assert target.read_text(encoding="utf-8") == "sensitive"


def test_command_tail_prints_last_lines_without_opening_older_rotation(
    monkeypatch, tmp_path, capsys
):
    root = tmp_path / "logs"
    _install_dataset(monkeypatch, root)
    active = root / "audit/auth.jsonl"
    active.parent.mkdir(parents=True)
    active.write_text("two\nthree\n", encoding="utf-8")
    older = active.parent / "auth.jsonl.1"
    older.write_text("one\n", encoding="utf-8")
    original = log_admin._last_lines
    reader = MagicMock(side_effect=original)
    monkeypatch.setattr(log_admin, "_last_lines", reader)

    assert log_admin.command_tail(_args(dataset="audit.auth", lines=2)) == 0
    reader.assert_called_once_with(active, 2)
    assert capsys.readouterr().out == "two\nthree\n"


def test_command_tail_combines_rotation_boundary_in_chronological_order(
    monkeypatch, tmp_path, capsys
):
    root = tmp_path / "logs"
    _install_dataset(monkeypatch, root)
    active = root / "audit/auth.jsonl"
    active.parent.mkdir(parents=True)
    (active.parent / "auth.jsonl.2").write_text("oldest\n", encoding="utf-8")
    (active.parent / "auth.jsonl.1").write_text("middle-a\nmiddle-b\n", encoding="utf-8")
    active.write_text("active\n", encoding="utf-8")

    assert log_admin.command_tail(_args(dataset="audit.auth", lines=3)) == 0
    assert capsys.readouterr().out == "middle-a\nmiddle-b\nactive\n"


def test_command_find_requires_exactly_one_identifier():
    with pytest.raises(ValueError, match="必须且只能指定一个 ID"):
        log_admin.command_find(_args())
    with pytest.raises(ValueError, match="必须且只能指定一个 ID"):
        log_admin.command_find(_args(request_id="r", task_id="t"))


def test_command_find_skips_bad_json_searches_sorted_datasets_and_honors_limit(
    monkeypatch, capsys
):
    monkeypatch.setattr(
        log_admin,
        "DATASET_PATHS",
        {"numoj.zeta": "zeta.jsonl", "numoj.alpha": "alpha.jsonl"},
    )
    visited = []

    def lines(dataset):
        visited.append(dataset)
        if dataset == "numoj.alpha":
            return iter(
                [
                    "not-json\n",
                    json.dumps(["not", "a", "mapping"]),
                    json.dumps({"request": {"id": "wanted"}, "seq": 1}),
                    json.dumps({"labels": {"request_id": "wanted"}, "seq": 2}),
                    json.dumps({"trace": {"id": "wanted"}, "seq": 3}),
                ]
            )
        return iter([json.dumps({"request": {"id": "wanted"}, "seq": 4})])

    monkeypatch.setattr(log_admin, "_iter_lines", lines)

    result = log_admin.command_find(_args(request_id="wanted", limit=2))

    assert result == 0
    assert visited == ["numoj.alpha"]
    output = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [row["seq"] for row in output] == [1, 2]


def test_command_find_limits_search_to_dataset_and_returns_one_when_missing(
    monkeypatch, capsys
):
    iterator = MagicMock(return_value=iter([json.dumps({"task": {"id": "other"}})]))
    monkeypatch.setattr(log_admin, "_iter_lines", iterator)

    result = log_admin.command_find(
        _args(task_id="wanted", dataset="task.lifecycle", limit=10)
    )

    assert result == 1
    iterator.assert_called_once_with("task.lifecycle")
    assert capsys.readouterr().out == ""


def test_command_find_matches_numeric_submission_id(monkeypatch, capsys):
    monkeypatch.setattr(
        log_admin,
        "_iter_lines",
        lambda _dataset: iter([json.dumps({"submission": {"id": 42}})]),
    )

    assert log_admin.command_find(
        _args(submission_id="42", dataset="audit.submissions")
    ) == 0
    assert json.loads(capsys.readouterr().out)["submission"]["id"] == 42


def test_command_validate_accepts_current_schema_across_rotation_files(
    monkeypatch, tmp_path, capsys
):
    root = tmp_path / "logs"
    _install_dataset(monkeypatch, root)
    active = root / "audit/auth.jsonl"
    active.parent.mkdir(parents=True)
    (active.parent / "auth.jsonl.1").write_text(
        json.dumps(_schema_event(event={"id": "old"})) + "\n",
        encoding="utf-8",
    )
    active.write_text(
        json.dumps(_schema_event(event={"id": "new"})) + "\n",
        encoding="utf-8",
    )

    assert log_admin.command_validate(_args(dataset="audit.auth")) == 0
    assert json.loads(capsys.readouterr().out) == {"checked": 2, "invalid": 0}


def test_command_validate_reports_all_invalid_lines_and_exit_one(
    monkeypatch, tmp_path, capsys
):
    root = tmp_path / "logs"
    _install_dataset(monkeypatch, root)
    active = root / "audit/auth.jsonl"
    active.parent.mkdir(parents=True)
    active.write_text(
        "not-json\n"
        + json.dumps({"schema": {"name": "wrong", "version": 1}})
        + "\n"
        + json.dumps(["not-a-mapping"])
        + "\n",
        encoding="utf-8",
    )

    assert log_admin.command_validate(_args(dataset="audit.auth", max_errors=20)) == 1
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"checked": 3, "invalid": 3}
    assert captured.err.splitlines() == [
        f"INVALID {active}:1",
        f"INVALID {active}:2",
        f"INVALID {active}:3",
    ]


def test_command_validate_stops_at_max_errors_and_prints_summary_to_stderr(
    monkeypatch, tmp_path, capsys
):
    root = tmp_path / "logs"
    _install_dataset(monkeypatch, root)
    active = root / "audit/auth.jsonl"
    active.parent.mkdir(parents=True)
    active.write_text("bad-one\nbad-two\nbad-three\n", encoding="utf-8")

    assert log_admin.command_validate(_args(dataset="audit.auth", max_errors=2)) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines() == [
        f"INVALID {active}:1",
        f"INVALID {active}:2",
        '{"checked": 2, "invalid": 2}',
    ]


def test_command_validate_without_dataset_visits_all_datasets(monkeypatch, capsys):
    monkeypatch.setattr(
        log_admin,
        "DATASET_PATHS",
        {"numoj.second": "second.jsonl", "numoj.first": "first.jsonl"},
    )
    paths = {
        "numoj.first": Path("/not-used/first.jsonl"),
        "numoj.second": Path("/not-used/second.jsonl"),
    }
    visited = []

    def dataset_path(dataset):
        visited.append(dataset)
        return paths[dataset]

    monkeypatch.setattr(log_admin, "_dataset_path", dataset_path)
    monkeypatch.setattr(log_admin, "_rotated_files", lambda _path: [])

    assert log_admin.command_validate(_args()) == 0
    assert visited == ["numoj.first", "numoj.second"]
    assert json.loads(capsys.readouterr().out) == {"checked": 0, "invalid": 0}


def _prepared_doctor_root(tmp_path: Path) -> Path:
    root = tmp_path / "logs"
    root.mkdir(mode=0o700)
    for relative in log_admin.LOG_DIRECTORIES:
        (root / relative).mkdir(mode=0o700)
    return root


def test_collector_lock_held_requires_an_exclusive_lock(tmp_path):
    lock_path = tmp_path / "collector.lock"
    assert log_admin._collector_lock_held(lock_path) is False

    lock_path.write_text("", encoding="utf-8")
    descriptor = os.open(lock_path, os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert log_admin._collector_lock_held(lock_path) is True
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
    assert log_admin._collector_lock_held(lock_path) is False

    target = tmp_path / "target.lock"
    target.write_text("", encoding="utf-8")
    lock_path.unlink()
    lock_path.symlink_to(target)
    assert log_admin._collector_lock_held(lock_path) is False


def test_command_doctor_returns_success_for_private_tree_socket_and_running_journal(
    monkeypatch, tmp_path, capsys
):
    root = _prepared_doctor_root(tmp_path)
    socket_path = root / "run/events.sock"
    socket_path.write_text("fake socket", encoding="utf-8")
    socket_path.chmod(0o600)
    journal = root / "state/journal-status.json"
    journal.write_text(json.dumps({"state": "running"}), encoding="utf-8")
    journal.chmod(0o600)
    monkeypatch.setattr(log_admin, "LOG_ROOT", root)
    monkeypatch.setattr(log_admin, "init_log_tree", lambda requested: requested)

    with (
        patch.object(log_admin.stat, "S_ISSOCK", return_value=True),
        patch.object(log_admin, "_socket_listener_ready", return_value=True),
        patch.object(log_admin, "_collector_lock_held", return_value=True),
    ):
        assert log_admin.command_doctor(_args()) == 0

    report = json.loads(capsys.readouterr().out)
    assert report == {
        "collector_lock_held": True,
        "issues": [],
        "journal": {"state": "running"},
        "log_root": str(root),
        "socket_ready": True,
    }


def test_command_doctor_reports_permissions_symlink_and_stopped_journal(
    monkeypatch, tmp_path, capsys
):
    root = _prepared_doctor_root(tmp_path)
    root.chmod(0o755)
    socket_path = root / "run/events.sock"
    socket_path.write_text("fake socket", encoding="utf-8")
    socket_path.chmod(0o666)
    journal = root / "state/journal-status.json"
    journal.write_text(json.dumps({"state": "retrying"}), encoding="utf-8")
    journal.chmod(0o644)
    outside = tmp_path / "outside"
    outside.write_text("secret", encoding="utf-8")
    (root / "audit/link").symlink_to(outside)
    monkeypatch.setattr(log_admin, "LOG_ROOT", root)
    monkeypatch.setattr(log_admin, "init_log_tree", lambda requested: requested)

    with (
        patch.object(log_admin.stat, "S_ISSOCK", return_value=True),
        patch.object(log_admin, "_socket_listener_ready", return_value=True),
        patch.object(log_admin, "_collector_lock_held", return_value=True),
    ):
        assert log_admin.command_doctor(_args()) == 1

    report = json.loads(capsys.readouterr().out)
    issues = "\n".join(report["issues"])
    assert "日志根目录权限过宽: 0755" in issues
    assert "采集器 socket 权限过宽" in issues
    assert "journald 采集未运行: retrying" in issues
    assert "日志树包含符号链接" in issues
    assert "日志文件权限过宽" in issues


def test_command_doctor_rejects_stale_unix_socket(monkeypatch, tmp_path, capsys):
    root = _prepared_doctor_root(tmp_path)
    socket_path = root / "run/events.sock"
    socket_path.write_text("stale socket", encoding="utf-8")
    socket_path.chmod(0o600)
    journal = root / "state/journal-status.json"
    journal.write_text(json.dumps({"state": "running"}), encoding="utf-8")
    journal.chmod(0o600)
    monkeypatch.setattr(log_admin, "LOG_ROOT", root)
    monkeypatch.setattr(log_admin, "init_log_tree", lambda requested: requested)

    with (
        patch.object(log_admin.stat, "S_ISSOCK", return_value=True),
        patch.object(log_admin, "_socket_listener_ready", return_value=False),
        patch.object(log_admin, "_collector_lock_held", return_value=True),
    ):
        assert log_admin.command_doctor(_args()) == 1

    report = json.loads(capsys.readouterr().out)
    assert report["socket_ready"] is False
    assert "采集器 socket 不可连接" in "\n".join(report["issues"])


def test_command_doctor_rejects_connectable_socket_without_held_lock(
    monkeypatch, tmp_path, capsys
):
    root = _prepared_doctor_root(tmp_path)
    socket_path = root / "run/events.sock"
    socket_path.write_text("stale socket", encoding="utf-8")
    socket_path.chmod(0o600)
    journal = root / "state/journal-status.json"
    journal.write_text(json.dumps({"state": "running"}), encoding="utf-8")
    journal.chmod(0o600)
    monkeypatch.setattr(log_admin, "LOG_ROOT", root)
    monkeypatch.setattr(log_admin, "init_log_tree", lambda requested: requested)

    with (
        patch.object(log_admin.stat, "S_ISSOCK", return_value=True),
        patch.object(log_admin, "_socket_listener_ready", return_value=True),
        patch.object(log_admin, "_collector_lock_held", return_value=False),
    ):
        assert log_admin.command_doctor(_args()) == 1

    report = json.loads(capsys.readouterr().out)
    assert report["collector_lock_held"] is False
    assert report["socket_ready"] is False
    assert "采集器锁未被持有" in "\n".join(report["issues"])


def test_command_doctor_reports_missing_socket_and_journal_status(
    monkeypatch, tmp_path, capsys
):
    root = _prepared_doctor_root(tmp_path)
    monkeypatch.setattr(log_admin, "LOG_ROOT", root)
    monkeypatch.setattr(log_admin, "init_log_tree", lambda requested: requested)

    assert log_admin.command_doctor(_args()) == 1

    report = json.loads(capsys.readouterr().out)
    assert report["socket_ready"] is False
    assert report["journal"] is None
    assert report["collector_lock_held"] is False
    assert report["issues"] == [
        "采集器锁未被持有，采集器可能未运行",
        "尚无有效的 journald 采集状态",
    ]


def test_command_doctor_reports_unsafe_log_subdirectory(monkeypatch, tmp_path, capsys):
    root = _prepared_doctor_root(tmp_path)
    audit = root / "audit"
    audit.rmdir()
    audit.write_text("not a directory", encoding="utf-8")
    audit.chmod(0o600)
    monkeypatch.setattr(log_admin, "LOG_ROOT", root)
    monkeypatch.setattr(log_admin, "init_log_tree", lambda requested: requested)

    assert log_admin.command_doctor(_args()) == 1
    report = json.loads(capsys.readouterr().out)
    assert any("日志子目录不安全" in issue for issue in report["issues"])


def test_main_runs_handler_and_returns_its_integer_result(monkeypatch, tmp_path):
    root = tmp_path / "logs"
    monkeypatch.setattr(log_admin, "LOG_ROOT", root)
    initializer = MagicMock(return_value=root)
    monkeypatch.setattr(log_admin, "init_log_tree", initializer)

    assert log_admin.main(["init"]) == 0
    initializer.assert_called_once_with(root)


def test_main_converts_safe_operational_errors_to_exit_two(monkeypatch, capsys):
    monkeypatch.setattr(
        log_admin,
        "_rotated_files",
        MagicMock(side_effect=OSError("permission denied")),
    )

    assert log_admin.main(["tail", "audit.auth"]) == 2
    assert capsys.readouterr().err == "日志工具失败: permission denied\n"


@pytest.mark.parametrize(
    "argv",
    [
        ["tail", "audit.auth", "--lines", "0"],
        ["find", "--request-id", "r", "--limit", "-1"],
    ],
)
def test_main_rejects_non_positive_quantity_arguments(argv):
    with pytest.raises(SystemExit) as error:
        log_admin.main(argv)
    assert error.value.code == 2


def test_main_returns_two_for_unknown_dataset_without_traceback(capsys):
    assert log_admin.main(["tail", "definitely.missing"]) == 2
    assert "未知 dataset" in capsys.readouterr().err
