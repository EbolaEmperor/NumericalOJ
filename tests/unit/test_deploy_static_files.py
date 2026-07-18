from pathlib import Path

import pytest

from deploy.static_files import classify, install, remove_recorded
from deploy.static_files import _parse_args


def test_static_install_is_no_clobber_and_records_only_created_file(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("new", encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    record = tmp_path / "installed.bin"

    assert classify(source, target, "static/assets/new.txt") == "MISSING"
    install(source, target, "static/assets/new.txt", record)

    destination = target / "static/assets/new.txt"
    assert destination.read_text(encoding="utf-8") == "new"
    recorded = record.read_bytes().split(b"\0")
    assert recorded[0] == b"static/assets/new.txt"
    assert len(recorded) == 4
    assert classify(source, target, "static/assets/new.txt") == "IDENTICAL"

    source.write_text("replacement", encoding="utf-8")
    with pytest.raises(FileExistsError):
        install(source, target, "static/assets/new.txt", record)
    assert destination.read_text(encoding="utf-8") == "new"
    assert record.read_bytes().split(b"\0")[0] == b"static/assets/new.txt"

    remove_recorded(target, record)
    assert not destination.exists()


def test_static_operations_refuse_symlinked_parent(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("secret", encoding="utf-8")
    target = tmp_path / "target"
    outside = tmp_path / "outside"
    (target / "static").mkdir(parents=True)
    outside.mkdir()
    (target / "static/assets").symlink_to(outside, target_is_directory=True)
    record = tmp_path / "installed.bin"

    with pytest.raises(OSError):
        classify(source, target, "static/assets/new.txt")
    with pytest.raises(OSError):
        install(source, target, "static/assets/new.txt", record)
    assert not (outside / "new.txt").exists()
    assert not record.exists()


def test_static_rollback_does_not_delete_a_replaced_file(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("ours", encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    record = tmp_path / "installed.bin"
    install(source, target, "static/item.txt", record)

    destination = target / "static/item.txt"
    destination.unlink()
    destination.write_text("someone else's", encoding="utf-8")

    with pytest.raises(RuntimeError):
        remove_recorded(target, record)
    assert destination.read_text(encoding="utf-8") == "someone else's"


def test_static_tool_has_no_unscoped_remove_command():
    with pytest.raises(SystemExit):
        _parse_args(["remove", "--target-root", "/tmp", "--relative", "static/a"])
