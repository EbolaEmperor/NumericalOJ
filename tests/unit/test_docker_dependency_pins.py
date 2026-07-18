import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _dockerfile(path):
    return (ROOT / path).read_text(encoding='utf-8')


def test_agent_judge_harness_dependencies_are_explicitly_versioned():
    dockerfile = _dockerfile('docker/agent_judge/Dockerfile')
    expected = {
        '@anthropic-ai/claude-code': 'CLAUDE_CODE_VERSION',
        '@openai/codex': 'CODEX_CLI_VERSION',
        'opencode-ai': 'OPENCODE_VERSION',
        '@ai-sdk/openai-compatible': 'AI_SDK_OPENAI_COMPATIBLE_VERSION',
        '@ai-sdk/anthropic': 'AI_SDK_ANTHROPIC_VERSION',
    }

    for package, build_arg in expected.items():
        assert re.search(rf'^ARG {build_arg}=\S+$', dockerfile, re.MULTILINE)
        assert f'{package}@${{{build_arg}}}' in dockerfile


def test_lite_agent_judge_uses_the_same_claude_code_pin():
    full = _dockerfile('docker/agent_judge/Dockerfile')
    lite = _dockerfile('docker/agent_judge-lite/Dockerfile')
    version_pattern = re.compile(r'^ARG CLAUDE_CODE_VERSION=(\S+)$', re.MULTILINE)

    assert version_pattern.search(full).group(1) == version_pattern.search(lite).group(1)
    assert '@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}' in lite
