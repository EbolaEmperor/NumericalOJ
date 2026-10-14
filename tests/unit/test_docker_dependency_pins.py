import re
from pathlib import Path

import pytest


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


def test_lite_agent_judge_uses_same_claude_and_pi_pins():
    full = _dockerfile('docker/agent_judge/Dockerfile')
    lite = _dockerfile('docker/agent_judge-lite/Dockerfile')
    version_pattern = re.compile(r'^ARG CLAUDE_CODE_VERSION=(\S+)$', re.MULTILINE)
    assert version_pattern.search(full).group(1) == version_pattern.search(lite).group(1)
    assert '@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}' in lite
    pi_version_pattern = re.compile(
        r'^ARG PI_CODING_AGENT_VERSION=(\S+)$', re.MULTILINE
    )
    assert pi_version_pattern.search(full).group(1) == '0.82.1'
    assert pi_version_pattern.search(lite).group(1) == '0.82.1'
    assert '@earendil-works/pi-coding-agent@${PI_CODING_AGENT_VERSION}' in full
    assert '@earendil-works/pi-coding-agent@${PI_CODING_AGENT_VERSION}' in lite
    assert 'npm install -g --ignore-scripts' in full
    assert 'npm install -g --ignore-scripts' in lite


def test_codex_bubblewrap_is_appended_after_harness_dependency_layers():
    for relative_path in (
        'docker/agent_judge/Dockerfile',
        'docker/agent_judge-lite/Dockerfile',
    ):
        dockerfile = _dockerfile(relative_path)
        harness_layer = dockerfile.index('npm install -g --ignore-scripts')
        bubblewrap_layer = dockerfile.index(
            'apt-get install -y --no-install-recommends bubblewrap'
        )
        assert bubblewrap_layer > harness_layer


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


@pytest.mark.parametrize(
    ('path', 'expected_base'),
    (
        (
            'docker/judger/Dockerfile',
            'debian:bookworm-slim@sha256:'
            '60eac759739651111db372c07be67863818726f754804b8707c90979bda511df',
        ),
        (
            'docker/agent_judge/Dockerfile',
            'node:24-bookworm@sha256:'
            'be23f54a88d34e8824c741b19b91064094f92c1c97b194144bfc8b50d67258e2',
        ),
        (
            'docker/agent_judge-lite/Dockerfile',
            'node:24.20.0-bookworm-slim@sha256:'
            'ba849c60be29959425b8734d57b8b4b7d56f98edd9504c9af091d5281095a71e',
        ),
        (
            'docker/lean4/Dockerfile',
            'debian:bookworm-slim@sha256:'
            'abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241',
        ),
        (
            'docker/judger-lite/Dockerfile',
            'debian:bookworm-slim@sha256:'
            'abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241',
        ),
        (
            'docker/vibehub-runtime/Dockerfile',
            'python:3.12-slim-bookworm@sha256:'
            'd50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b',
        ),
    ),
)
def test_docker_external_bases_follow_the_fixed_runtime_policy(path, expected_base):
    stages = set()
    external_bases = []
    for line in _dockerfile(path).splitlines():
        if not line.startswith('FROM '):
            continue
        words = line.split()
        base = words[1]
        if base not in stages and base != '${LEAN4_IMAGE}':
            external_bases.append(base)
        if len(words) == 4 and words[2].upper() == 'AS':
            stages.add(words[3])

    assert expected_base in external_bases
    assert all(
        re.fullmatch(r'[^@]+@sha256:[0-9a-f]{64}', base)
        for base in external_bases
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


def test_agent_judge_installs_cpu_only_pytorch_runtime():
    dockerfile = _dockerfile('docker/agent_judge/Dockerfile')
    torch_install = dockerfile.index('torch torchvision')
    cpu_index = dockerfile.index('https://download.pytorch.org/whl/cpu')

    assert cpu_index < torch_install
    assert 'nvidia-' not in dockerfile


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
