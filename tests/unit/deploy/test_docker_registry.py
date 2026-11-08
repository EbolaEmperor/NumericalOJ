"""官方 registry 切换保持 Dockerfile 的构建语义和版本引用。"""

import stat

import pytest

from deploy import docker_registry as registry


def test_hub_available_keeps_default_and_does_not_persist_choice(tmp_path):
    calls = []
    assert registry.select_registry(tmp_path, environ={}, probe=lambda url: calls.append(url) or True) == ""
    assert len(calls) == 2
    assert not (tmp_path / ".deploy").exists()


def test_hub_auth_failure_selects_official_ecr_and_persists_private_choice(tmp_path):
    value = registry.select_registry(tmp_path, environ={}, probe=lambda url: "auth.docker.io" not in url)
    assert value == registry.ECR_LIBRARY
    path = tmp_path / ".deploy/docker-library-registry"
    assert path.read_text().strip() == registry.ECR_LIBRARY
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert registry.select_registry(tmp_path, environ={}, probe=lambda url: pytest.fail("不应重新探测")) == value


def test_all_registries_unreachable_retains_hub_cache_without_guessing(tmp_path):
    assert registry.select_registry(tmp_path, environ={}, probe=lambda url: False) == ""
    assert not (tmp_path / ".deploy").exists()


def test_explicit_registry_and_explicit_hub_override_persistent_choice(tmp_path):
    assert registry.select_registry(tmp_path, environ={"NUMOJ_DOCKER_LIBRARY_REGISTRY": registry.ECR_LIBRARY}) == registry.ECR_LIBRARY
    assert registry.select_registry(tmp_path, environ={"NUMOJ_DOCKER_LIBRARY_REGISTRY": ""}) == ""
    assert registry.select_registry(tmp_path, environ={}) == ""


@pytest.mark.parametrize("value", ["https://example.com/library", "registry/library;touch bad", "../outside"])
def test_invalid_explicit_registry_fails_closed(tmp_path, value):
    with pytest.raises(registry.RegistryError, match="格式无效"):
        registry.select_registry(tmp_path, environ={"NUMOJ_DOCKER_LIBRARY_REGISTRY": value})


def test_rewrite_preserves_platform_tag_digest_comments_and_install_layers():
    source = (
        "# base\nARG LEAN4_IMAGE=numericaloj-lean4:latest\n"
        "FROM ${LEAN4_IMAGE} AS lean4\n"
        "FROM --platform=$BUILDPLATFORM node:24.20.0-bookworm-slim@sha256:existing AS runtime # keep\n"
        "RUN printf untouched\nCOPY --from=lean4 /opt/elan /opt/elan\n"
        "FROM python:3.12-slim\nFROM debian@sha256:existing\n"
    )
    rewritten = registry.rewrite_from(source, registry.ECR_LIBRARY)
    assert "FROM ${LEAN4_IMAGE} AS lean4\n" in rewritten
    assert f"FROM --platform=$BUILDPLATFORM {registry.ECR_LIBRARY}/node:24.20.0-bookworm-slim@sha256:existing AS runtime # keep\n" in rewritten
    assert "RUN printf untouched\nCOPY --from=lean4 /opt/elan /opt/elan\n" in rewritten
    assert f"FROM {registry.ECR_LIBRARY}/debian@sha256:existing\n" in rewritten
    assert registry.rewrite_from(source, "") == source


def test_existing_registry_third_party_local_candidates_and_stage_references_are_unchanged():
    source = (
        "FROM public.ecr.aws/docker/library/debian:bookworm AS python\n"
        "FROM python AS final\nFROM nvidia/cuda:12.6-runtime\n"
        "FROM numericaloj-lean4:deploy-run\nFROM scratch\n"
        "FROM docker.io/library/node:24\n"
    )
    assert registry.rewrite_from(source, registry.ECR_LIBRARY) == source


def test_temporary_dockerfile_keeps_original_and_crlf_bytes(tmp_path):
    source = tmp_path / "docker/agent/Dockerfile"
    source.parent.mkdir(parents=True)
    original = b"FROM python:3.12-slim\r\nRUN printf hi\r\n"
    source.write_bytes(original)
    output = registry.prepare_dockerfile(tmp_path, source, ".deploy/dockerfiles/run/agent.Dockerfile",
                                         registry=registry.ECR_LIBRARY)
    assert source.read_bytes() == original
    assert output.read_bytes() == original.replace(b"python:", (registry.ECR_LIBRARY + "/python:").encode())
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


@pytest.mark.parametrize("destination", ["docker/Dockerfile", "../outside.Dockerfile", ".deploy/dockerfiles",
                                         ".deploy/dockerfiles/run/../../../outside.Dockerfile"])
def test_output_cannot_overwrite_tracked_or_external_files(tmp_path, destination):
    source = tmp_path / "Dockerfile"
    source.write_text("FROM debian:bookworm\n")
    with pytest.raises(registry.RegistryError):
        registry.prepare_dockerfile(tmp_path, source, destination, registry=registry.ECR_LIBRARY)


def test_symlink_ancestor_cannot_redirect_deployment_artifacts(tmp_path):
    source = tmp_path / "Dockerfile"
    source.write_text("FROM debian:bookworm\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / ".deploy").symlink_to(outside, target_is_directory=True)
    with pytest.raises(registry.RegistryError, match="符号链接"):
        registry.prepare_dockerfile(tmp_path, source, ".deploy/dockerfiles/run.Dockerfile",
                                    registry=registry.ECR_LIBRARY)
    assert not list(outside.iterdir())
