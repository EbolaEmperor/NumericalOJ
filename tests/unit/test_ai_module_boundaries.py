import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _module_tree(module_path):
    return ast.parse((ROOT / module_path).read_text(encoding="utf-8"))


def test_ai_and_integrations_package_initializers_stay_lightweight():
    for relative_path in (
        "backend/oj_modules/ai/__init__.py",
        "backend/oj_modules/integrations/__init__.py",
    ):
        tree = _module_tree(relative_path)
        assert not any(
            isinstance(node, (ast.Import, ast.ImportFrom))
            for node in tree.body
        ), relative_path


def test_promptly_canonical_patch_point_controls_review(monkeypatch):
    from backend.oj_modules.ai import promptly

    def fake_call(_prompt_text, _endpoint, **_kwargs):
        return '{"nice": true}'

    monkeypatch.setattr(promptly, "_call_llm_text", fake_call)

    nice, reply = promptly.review_promptly_student_prompt(
        problem={"programming_grading_prompt": "简要题意"},
        student_prompt="使用单调队列维护窗口最值。",
        endpoint={
            "id": 1,
            "category": "text",
            "protocol": "openai",
            "base_url": "https://llm.example/v1",
            "api_key": "test-secret",
            "model": "test-model",
            "thinking_enabled": False,
            "thinking_format": "none",
        },
    )

    assert (nice, reply) == (True, "")
