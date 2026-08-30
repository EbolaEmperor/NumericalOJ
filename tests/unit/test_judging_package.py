from pathlib import Path

from backend.oj_modules.judging import case_runner, sandbox


def test_sandbox_mounts_the_canonical_sibling_case_runner():
    assert Path(sandbox._CASE_RUNNER_HOST_PATH).resolve() == Path(
        case_runner.__file__
    ).resolve()
    assert sandbox._CASE_PROTOCOL_PREFIX == case_runner.PROTOCOL_PREFIX
