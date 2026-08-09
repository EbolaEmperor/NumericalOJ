from types import SimpleNamespace

from oj_modules.agents import sessions as agent_sessions
from oj_modules.tasks.agent import titles


def test_title_generation_uses_selected_endpoint_once_and_sanitizes_output(
        monkeypatch):
    endpoint = {"id": 8, "model": "model-a"}
    calls = []

    def call_text(selected_endpoint, prompt, **kwargs):
        calls.append((selected_endpoint, prompt, kwargs))
        return SimpleNamespace(text="**任务标题：整理 MATLAB 数值实验附件并输出总结。**\n解释")

    monkeypatch.setattr(titles, "call_text", call_text)

    result = titles.generate_agent_title(
        endpoint,
        "请整理附件",
        fallback="回退标题",
    )

    assert result == "整理 MATLAB 数值实验附"
    assert len(result) <= 15
    assert len(calls) == 1
    assert calls[0][0] is endpoint
    assert calls[0][1] == "请整理附件"
    assert calls[0][2]["temperature"] == 0


def test_title_generation_failure_uses_bounded_deterministic_fallback(
        monkeypatch):
    monkeypatch.setattr(
        titles,
        "call_text",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("offline")),
    )

    result = titles.generate_agent_title(
        {"id": 8},
        "prompt",
        fallback="这是一个很长很长的任务回退标题文本",
    )

    assert result == "这是一个很长很长的任务回退标题"
    assert len(result) == 15


def test_initial_title_claim_prevents_duplicate_llm_calls_on_redelivery(
    monkeypatch,
):
    stored = {"title": ""}
    calls = []

    monkeypatch.setattr(
        agent_sessions,
        "get_agent_session",
        lambda _session_id: {
            "title": stored["title"],
            "is_legacy": False,
        },
    )

    def claim(_session_id, fallback):
        if stored["title"]:
            return False
        stored["title"] = fallback
        return True

    monkeypatch.setattr(
        agent_sessions,
        "claim_agent_session_title_generation",
        claim,
    )
    monkeypatch.setattr(
        titles,
        "call_text",
        lambda *_args, **_kwargs: (
            calls.append("called")
            or SimpleNamespace(text="模型生成标题")
        ),
    )

    first = titles.generate_initial_agent_session_title(
        "session-1",
        {"id": 8},
        "处理任务",
        fallback="确定性回退",
    )
    redelivery = titles.generate_initial_agent_session_title(
        "session-1",
        {"id": 8},
        "处理任务",
        fallback="确定性回退",
    )

    assert first == "模型生成标题"
    assert redelivery == "确定性回退"
    assert calls == ["called"]
