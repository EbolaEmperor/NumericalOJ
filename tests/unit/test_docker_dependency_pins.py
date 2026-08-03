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


def test_lite_agent_judge_uses_same_claude_pin_and_unpinned_pi():
    full = _dockerfile('docker/agent_judge/Dockerfile')
    lite = _dockerfile('docker/agent_judge-lite/Dockerfile')
    version_pattern = re.compile(r'^ARG CLAUDE_CODE_VERSION=(\S+)$', re.MULTILINE)
    assert version_pattern.search(full).group(1) == version_pattern.search(lite).group(1)
    assert '@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}' in lite
    assert 'PI_CODING_AGENT_VERSION' not in full
    assert 'PI_CODING_AGENT_VERSION' not in lite
    assert '@earendil-works/pi-coding-agent@' not in full
    assert '@earendil-works/pi-coding-agent@' not in lite
    assert '@earendil-works/pi-coding-agent' in full
    assert '@earendil-works/pi-coding-agent' in lite
    assert 'npm install -g --ignore-scripts' in full
    assert 'npm install -g --ignore-scripts' in lite


def test_lite_agent_judge_contains_every_selectable_harness():
    full = _dockerfile('docker/agent_judge/Dockerfile')
    lite = _dockerfile('docker/agent_judge-lite/Dockerfile')
    for build_arg, package in (
        ('CLAUDE_CODE_VERSION', '@anthropic-ai/claude-code'),
        ('CODEX_CLI_VERSION', '@openai/codex'),
        ('OPENCODE_VERSION', 'opencode-ai'),
    ):
        pattern = re.compile(rf'^ARG {build_arg}=(\S+)$', re.MULTILINE)
        assert pattern.search(lite).group(1) == pattern.search(full).group(1)
        assert f'{package}@${{{build_arg}}}' in lite


def test_production_docker_bases_follow_the_selected_runtime_policy():
    judger = _dockerfile('docker/judger/Dockerfile')
    agent = _dockerfile('docker/agent_judge/Dockerfile')
    lite_agent = _dockerfile('docker/agent_judge-lite/Dockerfile')

    assert (
        'FROM debian:bookworm-slim@sha256:'
        '60eac759739651111db372c07be67863818726f754804b8707c90979bda511df'
        in judger
    )
    assert 'FROM node:24-bookworm\n' in agent
    assert 'FROM node:24-bookworm-slim\n' in lite_agent


def test_agent_harness_args_do_not_invalidate_heavy_toolchain_cache():
    dockerfile = _dockerfile('docker/agent_judge/Dockerfile')

    heavy_tail = dockerfile.index(
        'RUN pip3 install --no-cache-dir --break-system-packages '
        '--force-reinstall "numpy<2"'
    )
    first_harness_arg = dockerfile.index('ARG CLAUDE_CODE_VERSION=')
    harness_install = dockerfile.index('RUN npm install -g')

    assert heavy_tail < first_harness_arg < harness_install


def test_agent_ai_sdk_pins_support_the_node_24_base():
    dockerfile = _dockerfile('docker/agent_judge/Dockerfile')

    assert 'ARG AI_SDK_OPENAI_COMPATIBLE_VERSION=2.0.51' in dockerfile
    assert 'ARG AI_SDK_ANTHROPIC_VERSION=3.0.85' in dockerfile


def test_agent_images_bundle_the_trusted_pi_web_search_mcp_extension():
    full = _dockerfile('docker/agent_judge/Dockerfile')
    lite = _dockerfile('docker/agent_judge-lite/Dockerfile')
    extension = (ROOT / 'docker/agent_judge/pi_web_search_mcp.ts').read_text(
        encoding='utf-8'
    )

    assert (
        'COPY pi_web_search_mcp.ts '
        '/usr/local/share/numoj/pi_web_search_mcp.ts'
    ) in full
    assert (
        'COPY agent_judge/pi_web_search_mcp.ts '
        '/usr/local/share/numoj/pi_web_search_mcp.ts'
    ) in lite
    assert 'pi.registerTool({' in extension
    assert 'name: "web_search"' in extension
    assert 'AJ_WEB_SEARCH_MCP_AUTHORIZATION' in extension
