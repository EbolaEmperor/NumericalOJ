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


def test_production_docker_bases_are_pinned_to_cached_digests():
    judger = _dockerfile('docker/judger/Dockerfile')
    agent = _dockerfile('docker/agent_judge/Dockerfile')

    assert (
        'FROM debian:bookworm-slim@sha256:'
        '60eac759739651111db372c07be67863818726f754804b8707c90979bda511df'
        in judger
    )
    assert (
        'FROM node:20-bookworm@sha256:'
        '8f693eaa7e0a8e71560c9a82b55fd54c2ae920a2ba5d2cde28bac7d1c01c9ba5'
        in agent
    )


def test_agent_harness_args_do_not_invalidate_heavy_toolchain_cache():
    dockerfile = _dockerfile('docker/agent_judge/Dockerfile')

    heavy_tail = dockerfile.index(
        'RUN pip3 install --no-cache-dir --break-system-packages '
        '--force-reinstall "numpy<2"'
    )
    first_harness_arg = dockerfile.index('ARG CLAUDE_CODE_VERSION=')
    harness_install = dockerfile.index('RUN npm install -g')

    assert heavy_tail < first_harness_arg < harness_install


def test_agent_ai_sdk_pins_support_the_cached_node_20_base():
    dockerfile = _dockerfile('docker/agent_judge/Dockerfile')

    assert 'ARG AI_SDK_OPENAI_COMPATIBLE_VERSION=2.0.51' in dockerfile
    assert 'ARG AI_SDK_ANTHROPIC_VERSION=3.0.85' in dockerfile
