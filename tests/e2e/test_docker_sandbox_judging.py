# -*- coding: utf-8 -*-
"""Docker sandbox judging e2e test: create problems for each language, upload
test data, submit correct solutions, and verify Accepted verdicts.

Requires Docker with the numericaloj-judger:latest image available.
"""

from __future__ import annotations

import json
import os
import subprocess
import time

import pytest

from backend.oj_modules.judging import core as judger_core
from tests.e2e.conftest import (
    create_problem,
    require_docker_judger_image,
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
        require_docker_judger_image()
        self._run_hello_world(cli, tmp_path, "cpp")

    def test_c_hello_world(self, cli, tmp_path):
        require_docker_judger_image()
        self._run_hello_world(cli, tmp_path, "c")

    def test_python_hello_world(self, cli, tmp_path):
        require_docker_judger_image()
        self._run_hello_world(cli, tmp_path, "python")

    def test_octave_hello_world(self, cli, tmp_path):
        require_docker_judger_image()
        self._run_hello_world(cli, tmp_path, "matlab")

    def test_batch_case_cannot_leave_setsid_daemon_for_next_case(
        self,
        tmp_path,
        monkeypatch,
    ):
        require_docker_judger_image()
        monkeypatch.setattr(
            judger_core,
            "JUDGER_RUN_ROOT",
            str(tmp_path / "judger"),
        )
        monkeypatch.setenv(
            "JUDGER_DOCKER_CASE_TMPFS_BYTES",
            str(8 * 1024 * 1024),
        )
        code = r'''
import os
import sys
import time

value = sys.stdin.read().strip()
if value == "first":
    base_is_read_only = False
    try:
        with open("/sandbox/shared.txt", "w", encoding="utf-8") as out:
            out.write("must not persist")
    except OSError:
        base_is_read_only = True
    os.mkdir("locked")
    with open("locked/child", "w", encoding="utf-8") as out:
        out.write("runner-owned")
    os.chmod("locked", 0)
    quota_enforced = False
    fd = os.open("fill.bin", os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.posix_fallocate(fd, 0, 16 * 1024 * 1024)
    except OSError:
        quota_enforced = True
    finally:
        os.close(fd)
    child = os.fork()
    if child == 0:
        os.setsid()
        devnull = os.open("/dev/null", os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(devnull, fd)
        while True:
            with open("/case/heartbeat", "ab", buffering=0) as out:
                out.write(b"x")
            time.sleep(0.005)
        os._exit(0)
    print(
        ("case0-base-ro" if base_is_read_only else "case0-base-rw")
        + ("-quota" if quota_enforced else "-no-quota"),
        flush=True,
    )
else:
    print(
        "compromised" if os.path.exists("/case/heartbeat") else "isolated",
        flush=True,
    )
'''

        result = judger_core.batch_evaluate(
            "python",
            {
                "sid": "eoj-batch-isolation",
                "code": code,
                "timeLimit": 2_000_000_000,
                "forbidden": "",
                "test_cases": [
                    {"input": "first"},
                    {"input": "second"},
                ],
            },
        )

        assert result["compile_result"]["status"] == "success"
        assert len(result["test_results"]) == 2
        assert (
            result["test_results"][0]["files"]["stdout"].strip()
            == "case0-base-ro-quota"
        )
        assert result["test_results"][1]["files"]["stdout"].strip() == "isolated"
        assert not any(
            name.startswith("case_")
            for name in os.listdir(
                os.path.join(
                    judger_core.JUDGER_RUN_ROOT,
                    "eoj-batch-isolation",
                )
            )
        )
        containers = subprocess.run(
            [
                "docker",
                "ps",
                "-a",
                "--filter",
                f"name=numoj-case-{os.getpid()}-",
                "--format",
                "{{.Names}}",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert containers.stdout.strip() == ""

    def test_case_rejects_symlink_and_oversized_output_artifacts(
        self,
        tmp_path,
        monkeypatch,
    ):
        require_docker_judger_image()
        monkeypatch.setattr(
            judger_core,
            "JUDGER_RUN_ROOT",
            str(tmp_path / "judger"),
        )
        code = r'''
import os
import sys

mode = sys.stdin.read().strip()
if mode == "symlink":
    os.symlink("/proc/self/environ", "output.txt")
    os.symlink("/proc/self/environ", "output.png")
    print("safe-symlink-fallback")
else:
    with open("output.txt", "wb") as out:
        out.write(b"x" * (1024 * 1024 + 1))
    print("safe-oversize-fallback")
'''
        result = judger_core.batch_evaluate(
            "python",
            {
                "sid": "eoj-batch-artifact-security",
                "code": code,
                "timeLimit": 2_000_000_000,
                "forbidden": "",
                "outputImageFilename": "output.png",
                "test_cases": [
                    {"input": "symlink"},
                    {"input": "oversize"},
                ],
            },
        )

        outputs = [
            item["files"]["stdout"].strip()
            for item in result["test_results"]
        ]
        assert outputs == [
            "safe-symlink-fallback",
            "safe-oversize-fallback",
        ]
        assert [
            item["status"]
            for item in result["test_results"]
        ] == [
            "Output Limit Exceeded",
            "Output Limit Exceeded",
        ]
        assert all(
            not any(
                str(name).lower().endswith(
                    (".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp")
                )
                for name in item["files"]
            )
            for item in result["test_results"]
        )
        assert all("PATH=" not in output for output in outputs)

    def test_runner_has_no_root_identity_groups_or_capabilities(
        self,
        tmp_path,
        monkeypatch,
    ):
        require_docker_judger_image()
        monkeypatch.setattr(
            judger_core,
            "JUDGER_RUN_ROOT",
            str(tmp_path / "judger"),
        )
        code = r'''
import json
import os

with open("/proc/self/status", "r", encoding="ascii") as handle:
    status_lines = handle.read().splitlines()
capabilities = {
    name: next(
        line.split()[1]
        for line in status_lines
        if line.startswith(name + ":")
    )
    for name in ("CapEff", "CapPrm", "CapAmb")
}

checks = {}
try:
    os.listdir("/export")
except PermissionError:
    checks["export_denied"] = True
else:
    checks["export_denied"] = False

try:
    os.setuid(0)
except PermissionError:
    checks["setuid_root_denied"] = True
else:
    checks["setuid_root_denied"] = False

try:
    os.kill(1, 0)
except PermissionError:
    checks["signal_root_denied"] = True
else:
    checks["signal_root_denied"] = False

print(json.dumps({
    "uid": os.getuid(),
    "gid": os.getgid(),
    "groups": os.getgroups(),
    "cap_eff": capabilities["CapEff"],
    "cap_permitted": capabilities["CapPrm"],
    "cap_ambient": capabilities["CapAmb"],
    **checks,
}, sort_keys=True))
'''

        result = judger_core.batch_evaluate(
            "python",
            {
                "sid": "eoj-runner-privilege-contract",
                "code": code,
                "timeLimit": 2_000_000_000,
                "forbidden": "",
                "test_cases": [{"input": ""}],
            },
        )

        test_result = result["test_results"][0]
        assert test_result["status"] == "Accepted"
        facts = json.loads(test_result["files"]["stdout"])
        assert facts == {
            "cap_eff": "0000000000000000",
            "cap_permitted": "0000000000000000",
            "cap_ambient": "0000000000000000",
            "export_denied": True,
            "gid": 65532,
            "groups": [],
            "setuid_root_denied": True,
            "signal_root_denied": True,
            "uid": 65532,
        }

    def test_public_image_from_one_case_is_not_mounted_into_next_case(
        self,
        tmp_path,
        monkeypatch,
    ):
        require_docker_judger_image()
        monkeypatch.setattr(
            judger_core,
            "JUDGER_RUN_ROOT",
            str(tmp_path / "judger"),
        )
        secret = b"case-zero-image-secret"
        code = f'''
import os
import sys

mode = sys.stdin.read().strip()
if mode == "first":
    with open("output.png", "wb") as handle:
        handle.write({secret!r})
    print("published")
else:
    candidate = "/sandbox/output_0.png"
    print("leaked" if os.path.exists(candidate) else "isolated")
'''

        result = judger_core.batch_evaluate(
            "python",
            {
                "sid": "eoj-batch-image-cross-case",
                "code": code,
                "timeLimit": 2_000_000_000,
                "forbidden": "",
                "outputImageFilename": "output.png",
                "test_cases": [
                    {"input": "first"},
                    {"input": "second"},
                ],
            },
        )

        assert [
            item["files"]["stdout"].strip()
            for item in result["test_results"]
        ] == ["published", "isolated"]
        artifact_dir = (
            tmp_path
            / "judger"
            / "eoj-batch-image-cross-case"
        )
        assert (artifact_dir / "output_0.png").read_bytes() == secret
        assert not (
            artifact_dir / "workspace" / "output_0.png"
        ).exists()

    def _run_hello_world(self, cli, tmp_path, lang_key: str):
        sol = SOLUTIONS[lang_key]
        cli.init_admin()

        title = f"DockerSandbox {lang_key} {int(time.time()*1000)}"
        problem_id = create_problem(
            cli,
            title,
            lang=sol["lang"],
            # Octave 的首次启动在 x86_64 Colima 中会稳定越过 1 秒；这个
            # 用例验证沙箱执行正确性，不把宿主模拟器冷启动性能当成判题失败。
            time_limit_ms=3000 if lang_key == "matlab" else 1000,
            submission_limit=10,
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
