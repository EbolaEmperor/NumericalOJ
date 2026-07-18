import os
from pathlib import Path

import pytest

from deploy.venv_integrity import seal, verify


REQUIREMENTS_SHA256 = "a" * 64


def _make_writable(root: Path) -> None:
    for current, directories, files in os.walk(root):
        os.chmod(current, Path(current).stat().st_mode | 0o700)
        for name in directories + files:
            path = Path(current) / name
            if not path.is_symlink():
                os.chmod(path, path.stat().st_mode | 0o600)


def test_sealed_venv_is_reusable_and_detects_content_tampering(tmp_path):
    venv = tmp_path / "venv"
    package = venv / "lib/python3.12/site-packages/example"
    package.mkdir(parents=True)
    module = package / "__init__.py"
    module.write_text("VERSION = 1\n", encoding="utf-8")
    (venv / ".numericaloj-requirements-sha256").write_text(
        REQUIREMENTS_SHA256 + "\n", encoding="utf-8"
    )

    try:
        seal(venv, REQUIREMENTS_SHA256)
        verify(venv, REQUIREMENTS_SHA256)

        os.chmod(venv, venv.stat().st_mode | 0o700)
        os.chmod(package, package.stat().st_mode | 0o700)
        os.chmod(module, module.stat().st_mode | 0o600)
        module.write_text("VERSION = 2\n", encoding="utf-8")
        os.chmod(module, module.stat().st_mode & ~0o222)
        os.chmod(package, package.stat().st_mode & ~0o222)
        os.chmod(venv, venv.stat().st_mode & ~0o222)

        with pytest.raises(ValueError, match="tree digest mismatch"):
            verify(venv, REQUIREMENTS_SHA256)
    finally:
        _make_writable(venv)


def test_sealed_venv_rejects_a_different_requirements_digest(tmp_path):
    venv = tmp_path / "venv"
    venv.mkdir()
    try:
        seal(venv, REQUIREMENTS_SHA256)
        with pytest.raises(ValueError, match="requirements_sha256"):
            verify(venv, "b" * 64)
    finally:
        _make_writable(venv)
