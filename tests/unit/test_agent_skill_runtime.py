# -*- coding: utf-8 -*-
"""NumOJ skill 的一次性 harness 投影。"""

from pathlib import Path

import pytest

from backend.oj_modules.tasks.agent import skill_runtime


_TARGETS = {
    "claude_code": Path(".runtime/home/.claude/skills"),
    "pi": Path(".runtime/pi/skills"),
}


@pytest.mark.parametrize("harness", ["claude_code", "pi"])
def test_materialize_numoj_user_skill_for_each_harness(tmp_path, harness):
    target = skill_runtime.materialize_skill(tmp_path, harness, "numoj-user")

    assert target == tmp_path / _TARGETS[harness] / "numoj-user"
    rendered = (target / "SKILL.md").read_text(encoding="utf-8")
    assert rendered.startswith("---\n")
    assert "name: numoj-user\n" in rendered
    assert "description:" in rendered
    canonical = (
        skill_runtime._SKILLS_ROOT / "numoj-user" / "SKILL.md"
    ).read_text(encoding="utf-8")
    _source_frontmatter, source_body = skill_runtime._split_frontmatter(canonical)
    _rendered_frontmatter, rendered_body = skill_runtime._split_frontmatter(rendered)
    assert rendered_body == source_body
    assert (target / "scripts").is_dir()
    assert not list(target.rglob("__pycache__"))
    assert not list(target.rglob("*.pyc"))
    assert not list(target.rglob(".DS_Store"))


def test_numoj_user_skill_documents_lean4_agent_workflow(tmp_path):
    target = skill_runtime.materialize_skill(tmp_path, "pi", "numoj-user")
    rendered = (target / "SKILL.md").read_text(encoding="utf-8")
    reference_path = target / "references" / "lean4-problems.md"
    reference = reference_path.read_text(encoding="utf-8")

    assert "references/lean4-problems.md" in rendered
    assert 'problem download <problem_id> -o /workspace' in reference
    assert "--workspace /workspace" in reference
    assert "numoj-problem.json" in reference
    assert "不会创建 Lake 工程" in reference
    assert "不要进入 skill 目录" in reference
    assert 'python3 "$NUMOJ_USER_CLI"' in rendered
    assert "Never `cd` into the skill directory" in rendered
    assert "problem lean-init" not in reference
    assert "readonly" in reference
    assert "writable" in reference
    for forbidden in ("`sorry`", "`admit`", "`axiom`"):
        assert forbidden in reference


def _write_synthetic_skill(root, frontmatter, body="# First\n"):
    source = root / "numoj-user"
    source.mkdir(parents=True, exist_ok=True)
    (source / "SKILL.md").write_text(
        f"---\n{frontmatter}---\n{body}", encoding="utf-8",
    )
    scripts = source / "scripts"
    scripts.mkdir()
    (scripts / "cli.py").write_text("print('ok')\n", encoding="utf-8")
    return source


def test_materialize_rereads_current_source_instead_of_using_a_copy(
        monkeypatch, tmp_path):
    skills_root = tmp_path / "canonical-skills"
    source = _write_synthetic_skill(
        skills_root,
        "name: numoj-user\ndescription: first version\n",
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(skill_runtime, "_SKILLS_ROOT", skills_root)

    target = skill_runtime.materialize_skill(workspace, "pi", "numoj-user")
    assert "first version" in (target / "SKILL.md").read_text(encoding="utf-8")

    (source / "SKILL.md").write_text(
        "---\nname: numoj-user\ndescription: second version\n---\n# Second\n",
        encoding="utf-8",
    )
    rematerialized = skill_runtime.materialize_skill(
        workspace, "pi", "numoj-user",
    )

    assert rematerialized == target
    rendered = (target / "SKILL.md").read_text(encoding="utf-8")
    assert "second version" in rendered
    assert "# Second" in rendered
    assert "first version" not in rendered


@pytest.mark.parametrize(
    (
        "harness",
        "keeps_allowed_tools",
        "keeps_user_invocable",
        "keeps_compatibility",
        "keeps_metadata",
    ),
    [
        ("claude_code", True, True, False, False),
        ("pi", True, False, True, True),
    ],
)
def test_materialize_filters_frontmatter_for_selected_harness(
        monkeypatch, tmp_path, harness, keeps_allowed_tools,
        keeps_user_invocable, keeps_compatibility, keeps_metadata):
    skills_root = tmp_path / "canonical-skills"
    _write_synthetic_skill(
        skills_root,
        (
            "name: numoj-user\n"
            "description: synthetic skill\n"
            "license: MIT\n"
            "compatibility: Linux\n"
            "metadata:\n"
            "  owner: numoj\n"
            "allowed-tools: Bash\n"
            "user-invocable: false\n"
            "unknown-harness-field: must-not-leak\n"
        ),
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(skill_runtime, "_SKILLS_ROOT", skills_root)

    target = skill_runtime.materialize_skill(workspace, harness, "numoj-user")
    rendered = (target / "SKILL.md").read_text(encoding="utf-8")

    assert ("license: MIT" in rendered) is (harness != "claude_code")
    assert ("compatibility: Linux" in rendered) is keeps_compatibility
    assert ("metadata:\n  owner: numoj" in rendered) is keeps_metadata
    assert ("allowed-tools: Bash" in rendered) is keeps_allowed_tools
    assert ("user-invocable: false" in rendered) is keeps_user_invocable
    assert "unknown-harness-field" not in rendered


@pytest.mark.parametrize("harness", ["", "unknown", "claude"])
def test_materialize_rejects_unknown_harness(tmp_path, harness):
    with pytest.raises(ValueError, match="harness"):
        skill_runtime.materialize_skill(tmp_path, harness, "numoj-user")


@pytest.mark.parametrize("source_skill", ["", "../numoj-user", "other"])
def test_materialize_rejects_untrusted_source_name(tmp_path, source_skill):
    with pytest.raises(ValueError, match="source skill"):
        skill_runtime.materialize_skill(tmp_path, "pi", source_skill)


def test_materialize_rejects_symlinked_source_root(monkeypatch, tmp_path):
    skills_root = tmp_path / "canonical-skills"
    real_source = tmp_path / "real-source"
    real_source.mkdir()
    (real_source / "SKILL.md").write_text(
        "---\nname: numoj-user\ndescription: unsafe\n---\n", encoding="utf-8",
    )
    skills_root.mkdir()
    (skills_root / "numoj-user").symlink_to(real_source, target_is_directory=True)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(skill_runtime, "_SKILLS_ROOT", skills_root)

    with pytest.raises(ValueError, match="不安全"):
        skill_runtime.materialize_skill(workspace, "pi", "numoj-user")


def test_materialize_rejects_symlink_inside_source(monkeypatch, tmp_path):
    skills_root = tmp_path / "canonical-skills"
    source = _write_synthetic_skill(
        skills_root, "name: numoj-user\ndescription: unsafe child\n",
    )
    (source / "linked-secret").symlink_to(tmp_path / "secret")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(skill_runtime, "_SKILLS_ROOT", skills_root)

    with pytest.raises(ValueError, match="普通文件"):
        skill_runtime.materialize_skill(workspace, "pi", "numoj-user")


def test_materialize_rejects_malformed_or_mismatched_frontmatter(
        monkeypatch, tmp_path):
    skills_root = tmp_path / "canonical-skills"
    source = _write_synthetic_skill(
        skills_root, "name: numoj-admin\ndescription: wrong identity\n",
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(skill_runtime, "_SKILLS_ROOT", skills_root)

    with pytest.raises(ValueError, match="name"):
        skill_runtime.materialize_skill(workspace, "pi", "numoj-user")

    (source / "SKILL.md").write_text(
        "name: numoj-user\ndescription: no delimiter\n", encoding="utf-8",
    )
    with pytest.raises(ValueError, match="frontmatter"):
        skill_runtime.materialize_skill(workspace, "pi", "numoj-user")
