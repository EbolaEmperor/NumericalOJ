# -*- coding: utf-8 -*-
"""书面作业 TeX 编译必须复用有界 tmpfs sandbox。"""

import os

from oj_modules import docker_sandbox
from oj_modules.tasks import written_homework_tasks


def test_tex_pipeline_runs_once_in_tmpfs_and_exports_only_pdf(
    tmp_path,
    monkeypatch,
):
    tex_path = tmp_path / "main.tex"
    tex_path.write_text(
        "\\documentclass{article}\\begin{document}ok\\end{document}",
        encoding="utf-8",
    )
    calls = []

    def fake_run_case(command, **kwargs):
        calls.append((list(command), dict(kwargs)))
        return docker_sandbox._RunResult(
            0,
            "[xelatex #1]\nok",
            "",
            123,
            artifacts={"main.pdf": b"%PDF-1.7\nsafe"},
        )

    monkeypatch.setattr(
        docker_sandbox,
        "run_case_in_container",
        fake_run_case,
    )

    ok, pdf_path, log = written_homework_tasks._compile_tex_with_xelatex(
        tex_path,
        tmp_path,
        timeout_seconds=12,
    )

    assert ok is True
    assert pdf_path == str(tmp_path / "main.pdf")
    assert (tmp_path / "main.pdf").read_bytes() == b"%PDF-1.7\nsafe"
    assert "[xelatex #1]" in log
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command[:2] == ["/bin/sh", "-c"]
    assert command[-3:] == ["/sandbox/main.tex", "main", "12"]
    assert kwargs["run_dir"] == str(tmp_path)
    assert kwargs["document_name"] == "main.pdf"
    assert kwargs["document_max_bytes"] == 64 * 1024 * 1024
    assert kwargs["timeout_sec"] == 68


def test_pdf_publish_replaces_symlink_without_touching_target(tmp_path):
    protected = tmp_path / "protected.pdf"
    protected.write_bytes(b"do not overwrite")
    target = tmp_path / "main.pdf"
    target.symlink_to(protected)

    written_homework_tasks._publish_compiled_pdf(
        str(tmp_path),
        "main.pdf",
        b"%PDF safe",
    )

    assert protected.read_bytes() == b"do not overwrite"
    assert not target.is_symlink()
    assert target.read_bytes() == b"%PDF safe"
    assert target.stat().st_uid == os.geteuid()
    assert target.stat().st_mode & 0o777 == 0o644


def test_tex_pipeline_rejects_missing_exported_pdf(tmp_path, monkeypatch):
    tex_path = tmp_path / "main.tex"
    tex_path.write_text("\\bye", encoding="utf-8")
    monkeypatch.setattr(
        docker_sandbox,
        "run_case_in_container",
        lambda *_args, **_kwargs: docker_sandbox._RunResult(
            0,
            "compiler claimed success",
            "",
            1,
        ),
    )

    ok, pdf_path, log = written_homework_tasks._compile_tex_with_xelatex(
        tex_path,
        tmp_path,
    )

    assert ok is False
    assert pdf_path is None
    assert "未找到生成的 PDF" in log
