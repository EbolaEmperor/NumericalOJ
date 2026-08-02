#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask

from oj_modules.judging import core as judger_core
from oj_modules.routes import submission_routes


def _build_app(monkeypatch, submission):
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.secret_key = "test-only"
    app.register_blueprint(submission_routes.submission_bp)
    monkeypatch.setattr(
        submission_routes,
        "current_user",
        lambda: {"id": 7, "username": "alice", "is_admin": 0},
    )
    monkeypatch.setattr(
        submission_routes,
        "is_admin",
        lambda _user: False,
    )
    monkeypatch.setattr(
        submission_routes,
        "get_submission_by_id",
        lambda _submission_id: dict(submission),
    )
    return app


def test_submission_image_route_never_follows_container_symlink(
    tmp_path,
    monkeypatch,
):
    run_root = tmp_path / "judger"
    run_dir = run_root / "eoj-batch-91"
    run_dir.mkdir(parents=True)
    (run_dir / "output_0.png").symlink_to("/proc/self/environ")
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(run_root))
    app = _build_app(
        monkeypatch,
        {
            "id": 91,
            "username": "alice",
            "test_points": [
                {
                    "has_output_image": True,
                    "output_image_filename": "output_0.png",
                }
            ],
        },
    )

    response = app.test_client().get("/submission_output_image/91/1")

    assert response.status_code == 404
    assert b"Output image not found" in response.data


def test_submission_image_route_streams_only_fixed_regular_inode(
    tmp_path,
    monkeypatch,
):
    run_root = tmp_path / "judger"
    run_dir = run_root / "eoj-batch-92"
    run_dir.mkdir(parents=True)
    image = run_dir / "output_0.png"
    image.write_bytes(b"\x89PNG safe")
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(run_root))
    app = _build_app(
        monkeypatch,
        {
            "id": 92,
            "username": "alice",
            "test_points": [
                {
                    "has_output_image": True,
                    "output_image_filename": "output_0.png",
                }
            ],
        },
    )

    response = app.test_client().get("/submission_output_image/92/1")

    assert response.status_code == 200
    assert response.data == b"\x89PNG safe"
