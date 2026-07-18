from pathlib import Path

import pytest

from deploy.manifest import ExcludeRules, build_manifest


ROOT = Path(__file__).resolve().parents[2]


def test_manifest_uses_rsync_excludes_as_its_single_rule_source():
    rules = ExcludeRules.load(ROOT / "deploy/rsync-excludes.txt")
    included, nul_paths = build_manifest(
        [
            "oj.py",
            "config.py",
            "static/app.js",
            "tmp/run.txt",
            "package/cache.pyc",
            "docs/maintenance.md",
        ],
        rules,
    )

    assert included == ["docs/maintenance.md", "oj.py"]
    assert nul_paths == b"docs/maintenance.md\0oj.py\0"


def test_manifest_rejects_unsafe_paths_and_unknown_exclude_syntax(tmp_path):
    rules = ExcludeRules.load(ROOT / "deploy/rsync-excludes.txt")
    with pytest.raises(ValueError, match="unsafe deploy path"):
        build_manifest(["../config.py"], rules)

    invalid = tmp_path / "excludes.txt"
    invalid.write_text("/**/secret\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported deploy exclude"):
        ExcludeRules.load(invalid)
