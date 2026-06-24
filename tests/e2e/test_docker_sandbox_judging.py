# -*- coding: utf-8 -*-
"""Docker sandbox judging e2e test: create problems for each language, upload
test data, submit correct solutions, and verify Accepted verdicts.

Requires Docker with the numericaloj-judger:latest image available.
"""

from __future__ import annotations

import time

import pytest

from tests.e2e.conftest import (
    create_problem,
    find_problem_id,
    write_zip,
)


HELLO_WORLD_TESTDATA = {"1.in": "", "1.out": "Hello World\n"}

SOLUTIONS = {
    "cpp": {
        "lang": "cpp",
        "code": '#include <iostream>\nusing namespace std;\nint main() { cout << "Hello World" << endl; return 0; }',
    },
    "c": {
        "lang": "c",
        "code": '#include <stdio.h>\nint main() { printf("Hello World\\n"); return 0; }',
    },
    "python": {
        "lang": "python",
        "code": 'print("Hello World")',
    },
    "matlab": {
        "lang": "matlab",
        "code": 'disp("Hello World")',
    },
}


def _wait_for_verdict(cli, submission_id: int, timeout: float = 60.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = cli.admin_json("submission", "status", str(submission_id))
        if not result.get("is_judging", True):
            return result
        time.sleep(1.0)
    pytest.fail(f"Submission {submission_id} did not finish within {timeout}s")


@pytest.mark.e2e
@pytest.mark.judger
class TestDockerSandboxJudging:
    """Verify that Docker-based judging works for all supported languages."""

    def test_cpp_hello_world(self, cli, tmp_path):
        self._run_hello_world(cli, tmp_path, "cpp")

    def test_c_hello_world(self, cli, tmp_path):
        self._run_hello_world(cli, tmp_path, "c")

    def test_python_hello_world(self, cli, tmp_path):
        self._run_hello_world(cli, tmp_path, "python")

    def test_octave_hello_world(self, cli, tmp_path):
        self._run_hello_world(cli, tmp_path, "matlab")

    def _run_hello_world(self, cli, tmp_path, lang_key: str):
        sol = SOLUTIONS[lang_key]
        cli.init_admin()

        title = f"DockerSandbox {lang_key} {int(time.time()*1000)}"
        problem_id = create_problem(
            cli, title, lang=sol["lang"], submission_limit=10,
        )

        testdata_zip = write_zip(
            tmp_path / f"testdata_{lang_key}.zip", HELLO_WORLD_TESTDATA
        )
        assert cli.admin_json(
            "problem", "upload-testdata", str(problem_id), str(testdata_zip)
        )["success"] is True

        submit_result = cli.admin_json(
            "problem", "submit", str(problem_id), "--code", sol["code"]
        )
        assert submit_result["success"] is True
        submission_id = submit_result["submission_id"]

        verdict = _wait_for_verdict(cli, submission_id)
        assert verdict["status"] == "Accepted", (
            f"Expected Accepted for {lang_key}, got {verdict['status']}. "
            f"Test points: {verdict.get('test_points')}"
        )
        assert verdict["score"] >= 1
