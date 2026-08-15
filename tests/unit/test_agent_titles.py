from types import SimpleNamespace

from oj_modules.agents import sessions as agent_sessions
from oj_modules.tasks.agent import titles


EXPECTED_TITLE_SYSTEM_PROMPT = (
    "你是一个任务意图概括专家。对于用户给定的一段话，请你用 15 字左右的标题精准地"
    "概括用户的任务与意图，作为这个任务的标题。请你直接输出你概括的标题，不要包含任何"
    "其它内容。要精准概括，能概括出用户的具体任务，不要太宽泛。再次强调：直接输出你概括"
    "的标题，15 字左右，不含其它内容。"
)


def test_title_generation_uses_lowest_input_price_and_sanitizes_output(
        monkeypatch):
    cheap = {
        "id": 8, "model": "cheap", "category": "text", "api_key": "secret",
        "input_price_per_million": "0.5",
    }
    expensive = {
        "id": 9, "model": "expensive", "category": "omni", "api_key": "secret",
        "input_price_per_million": "2",
    }
    raw_message = "请整理附件\n并保留首轮消息的原始换行"
    calls = []

    def call_text(selected_endpoint, prompt, **kwargs):
        calls.append((selected_endpoint, prompt, kwargs))
        return SimpleNamespace(text="**任务标题：整理 MATLAB 数值实验附件并输出总结。**\n解释")

    monkeypatch.setattr(titles, "call_text", call_text)
    monkeypatch.setattr(
        titles,
        "list_llm_endpoints",
        lambda **_kwargs: [expensive, cheap],
    )

    result = titles.generate_agent_title(
        raw_message,
        fallback="回退标题",
    )

    assert result == "整理 MATLAB 数值实验附件并输出总结"
    assert len(calls) == 1
    assert calls[0][0] is cheap
    assert calls[0][1] == raw_message
    assert calls[0][2]["system_prompt"] == EXPECTED_TITLE_SYSTEM_PROMPT
    assert calls[0][2]["temperature"] == 0
    assert calls[0][2]["max_tokens"] == 64
    assert calls[0][2]["timeout"] == 30


def test_title_generation_retries_second_cheapest_then_uses_fifteen_characters(
        monkeypatch):
    endpoints = [
        {
            "id": 8, "category": "text", "api_key": "a",
            "input_price_per_million": "1",
        },
        {
            "id": 9, "category": "text", "api_key": "b",
            "input_price_per_million": "2",
        },
        {
            "id": 10, "category": "text", "api_key": "c",
            "input_price_per_million": "3",
        },
    ]
    calls = []
    monkeypatch.setattr(titles, "list_llm_endpoints", lambda **_kwargs: endpoints)

    def fail(endpoint, *_args, **_kwargs):
        calls.append(endpoint["id"])
        raise RuntimeError("offline")

    monkeypatch.setattr(titles, "call_text", fail)

    result = titles.generate_agent_title(
        "一二三四五六七八九十甲乙丙丁戊己庚辛",
    )

    assert calls == [8, 9]
    assert result == "一二三四五六七八九十甲乙丙丁戊"


def test_free_title_generation_has_bounded_input(monkeypatch):
    endpoint = {
        "id": 8,
        "category": "text",
        "api_key": "secret",
        "input_price_per_million": "1",
    }
    calls = []
    monkeypatch.setattr(titles, "list_llm_endpoints", lambda **_kwargs: [endpoint])
    monkeypatch.setattr(
        titles,
        "call_text",
        lambda selected, prompt, **kwargs: (
            calls.append((selected, prompt, kwargs))
            or SimpleNamespace(text="有界标题")
        ),
    )

    assert titles.generate_agent_title("任" * 5000) == "有界标题"
    assert len(calls[0][1]) == 4000
    assert calls[0][2]["max_tokens"] == 64


def test_initial_title_claim_prevents_duplicate_llm_calls_on_redelivery(
    monkeypatch,
):
    stored = {"title": ""}
    endpoint = {
        "id": 8, "model": "global-cheapest", "category": "text",
        "api_key": "secret", "input_price_per_million": "1",
    }
    first_user_message = "用 MATLAB 设计自适应积分题"
    calls = []

    monkeypatch.setattr(
        agent_sessions,
        "get_agent_session",
        lambda _session_id: {
            "title": stored["title"],
            "is_legacy": False,
        },
    )
    monkeypatch.setattr(
        titles,
        "list_llm_endpoints",
        lambda **_kwargs: [endpoint],
    )
    monkeypatch.setattr(
        agent_sessions,
        "get_agent_session_turns",
        lambda _session_id: [{
            "turn_index": 1,
            "user_message": first_user_message,
        }],
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
        lambda selected_endpoint, prompt, **kwargs: (
            calls.append((selected_endpoint, prompt, kwargs))
            or SimpleNamespace(text="模型生成标题")
        ),
    )

    first = titles.generate_initial_agent_session_title(
        "session-1",
        (
            f"{first_user_message}\n\n"
            "用户随本轮消息上传了以下附件，文件已经放入 workspace。"
        ),
        fallback="确定性回退",
    )
    redelivery = titles.generate_initial_agent_session_title(
        "session-1",
        "处理任务",
        fallback="确定性回退",
    )

    assert first == "模型生成标题"
    assert redelivery == "确定性回退"
    assert len(calls) == 1
    assert calls[0][0] is endpoint
    assert calls[0][1] == first_user_message
    assert calls[0][2]["system_prompt"] == EXPECTED_TITLE_SYSTEM_PROMPT


def test_missing_first_turn_message_does_not_send_runtime_prompt(monkeypatch):
    monkeypatch.setattr(
        agent_sessions,
        "get_agent_session",
        lambda _session_id: {"title": "", "is_legacy": False},
    )
    monkeypatch.setattr(
        agent_sessions,
        "get_agent_session_turns",
        lambda _session_id: [],
    )
    monkeypatch.setattr(
        agent_sessions,
        "claim_agent_session_title_generation",
        lambda _session_id, _fallback: True,
    )
    monkeypatch.setattr(
        titles,
        "call_text",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("不得把运行期扩展 prompt 发给标题 LLM")
        ),
    )

    result = titles.generate_initial_agent_session_title(
        "session-missing-turn",
        "原消息\n\n运行期追加的附件路径",
        fallback="安全回退标题",
    )

    assert result == "安全回退标题"
