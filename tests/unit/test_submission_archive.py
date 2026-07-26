# -*- coding: utf-8 -*-
import json
import os
from datetime import datetime

from oj_modules import judger_core
from oj_modules import submission_archive


def test_archive_programming_submission_keeps_code_and_meta(tmp_path, monkeypatch):
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(tmp_path))
    submission = {
        "id": 42,
        "problem_id": 7,
        "problem_type": 1,
        "username": "alice",
        "code": "print('ok')\n",
        "status": "Pending",
        "created_at": datetime(2026, 7, 1, 12, 0, 0),
    }
    problem = {"id": 7, "title": "题目", "content": "原始题面", "type": 1, "lang": "python"}
    user = {"email": "alice@example.com"}
    classes = [{"class_en": "c1", "class_cn": "一班"}]

    archive_dir = submission_archive.archive_submission_record(submission, problem, user, classes)

    assert os.path.isfile(os.path.join(archive_dir, "code.py"))
    with open(os.path.join(archive_dir, "code.py"), encoding="utf-8") as f:
        assert f.read() == "print('ok')\n"
    with open(os.path.join(archive_dir, "meta.json"), encoding="utf-8") as f:
        meta = json.load(f)
    assert meta["problem_id"] == 7
    assert meta["problem_title"] == "题目"
    assert meta["problem_content"] == "原始题面"
    assert meta["username"] == "alice"
    assert meta["email"] == "alice@example.com"
    assert meta["submitted_at"] == "2026-07-01 12:00:00"
    assert meta["classes"][0]["class_en"] == "c1"
    assert "is_primary" not in meta["classes"][0]


def test_archive_promptly_submission_keeps_prompt(tmp_path, monkeypatch):
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(tmp_path))
    submission = {
        "id": 43,
        "problem_id": 8,
        "problem_type": 1,
        "username": "bob",
        "prompt_text": "solve it carefully",
        "generated_from_prompt": 1,
        "code": "int main(){}\n",
    }
    problem = {"id": 8, "title": "Prompt题", "content": "题面", "type": 1, "lang": "cpp"}

    archive_dir = submission_archive.archive_submission_record(submission, problem, {}, [])

    assert os.path.isfile(os.path.join(archive_dir, "prompt.txt"))
    assert not os.path.exists(os.path.join(archive_dir, "generated_code.cpp"))
    assert not os.path.exists(os.path.join(archive_dir, "code.cpp"))
    with open(os.path.join(archive_dir, "prompt.txt"), encoding="utf-8") as f:
        assert f.read() == "solve it carefully"


def test_archive_uploaded_original_file(tmp_path, monkeypatch):
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(tmp_path))
    source = tmp_path / "main.tex"
    source.write_text("\\section{A}\n", encoding="utf-8")

    copied = submission_archive.archive_uploaded_submission_file(44, str(source), "main.tex")

    assert os.path.basename(copied) == "submitted.tex"
    assert os.path.isfile(copied)
    with open(copied, encoding="utf-8") as f:
        assert f.read() == "\\section{A}\n"
