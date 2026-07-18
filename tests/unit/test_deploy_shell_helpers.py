from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
HELPERS = ROOT / "deploy" / "shell_helpers.sh"


def _bash(script, *args):
    return subprocess.run(
        ["bash", "-c", f'source "$1"; shift; {script}', "bash", str(HELPERS), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def test_safe_deploy_path_rejects_absolute_and_parent_traversal():
    for unsafe in ("", ".", "..", "../secret", "a/../secret", "a/..", "/etc/passwd"):
        assert _bash('numoj_is_safe_path "$1"', unsafe).returncode != 0

    assert _bash('numoj_is_safe_path "$1"', "deploy/supervisor/web.conf").returncode == 0


def test_atomic_symlink_never_leaves_a_regular_current_file(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    current = tmp_path / "current"

    result = _bash(
        'numoj_atomic_symlink "$1" "$2" test-token',
        str(first),
        str(current),
    )
    assert result.returncode == 0, result.stderr
    assert current.is_symlink()
    assert current.resolve() == first

    result = _bash(
        'numoj_atomic_symlink "$1" "$2" test-token',
        str(second),
        str(current),
    )
    assert result.returncode == 0, result.stderr
    assert current.is_symlink()
    assert current.resolve() == second


def test_disk_headroom_check_fails_closed(tmp_path):
    accepted = _bash(
        'numoj_require_free_bytes "$1" 0 test-filesystem',
        str(tmp_path),
    )
    assert accepted.returncode == 0, accepted.stderr

    rejected = _bash(
        'numoj_require_free_bytes "$1" 999999999999999999999 test-filesystem',
        str(tmp_path),
    )
    assert rejected.returncode != 0
    assert "磁盘余量不足" in rejected.stderr
