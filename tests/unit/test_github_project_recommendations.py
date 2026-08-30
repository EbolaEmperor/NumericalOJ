from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROJECT_SOURCE = (
    ROOT / "frontend/public/static/app/github-projects.js"
).read_text(encoding="utf-8")


def test_recommendations_randomly_sample_three_unique_projects():
    assert "Math.random" in PROJECT_SOURCE
    assert "selectRandomProjects(3)" in PROJECT_SOURCE
    assert "shuffled.slice(0, count)" in PROJECT_SOURCE
    assert "showNextProjectGroup" not in PROJECT_SOURCE
    assert "replaceChildren" in PROJECT_SOURCE


def test_recommendations_render_the_canonical_repository_name_safely():
    assert "copy.textContent = repository" in PROJECT_SOURCE
    assert "https://github.com/${repository}" in PROJECT_SOURCE
    assert 'link.rel = "noopener noreferrer"' in PROJECT_SOURCE
