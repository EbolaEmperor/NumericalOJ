import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile

import pytest

from oj_modules.vibehub import runtime


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "deploy_vibehub_base_oci", ROOT / "deploy" / "vibehub_base_oci.py"
)
oci = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(oci)


def _layer_bytes() -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as layer:
        payload = b"trusted base fixture\n"
        member = tarfile.TarInfo("fixture.txt")
        member.size = len(payload)
        member.mode = 0o644
        layer.addfile(member, io.BytesIO(payload))
    return stream.getvalue()


def _docker_archive(
    path: Path,
    *,
    diff_id: str | None = None,
    extra=None,
    config_marker: str = "fixture",
):
    layer_raw = _layer_bytes()
    actual_diff_id = "sha256:" + hashlib.sha256(layer_raw).hexdigest()
    config_raw = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "created": config_marker,
            "config": {"User": "65532:65532"},
            "rootfs": {"type": "layers", "diff_ids": [diff_id or actual_diff_id]},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    image_id = "sha256:" + hashlib.sha256(config_raw).hexdigest()
    config_name = image_id.removeprefix("sha256:") + ".json"
    layer_name = "fixture/layer.tar"
    manifest_raw = json.dumps(
        [{"Config": config_name, "RepoTags": ["candidate:test"], "Layers": [layer_name]}],
        separators=(",", ":"),
    ).encode()
    with tarfile.open(path, mode="w") as archive:
        for name, raw in (
            (config_name, config_raw),
            (layer_name, layer_raw),
            ("manifest.json", manifest_raw),
        ):
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            member.mode = 0o600
            archive.addfile(member, io.BytesIO(raw))
        if extra is not None:
            archive.addfile(extra)
    return image_id


def _converted_release(tmp_path: Path):
    root = tmp_path / "oci"
    releases = root / "releases"
    releases.mkdir(parents=True, mode=0o700)
    archive = tmp_path / "image.tar"
    image_id = _docker_archive(archive)
    release = releases / image_id.removeprefix("sha256:")
    info = oci.convert_docker_archive(
        archive,
        release,
        engine_image_ref="numericaloj-vibehub-runtime:1",
        engine_image_id=image_id,
    )
    return root, release, info


def _rewrite_release_manifest(release: Path, mutate) -> None:
    metadata_path = release / "metadata.json"
    index_path = release / "index.json"
    blob_root = release / "blobs" / "sha256"
    metadata = json.loads(metadata_path.read_text())
    index = json.loads(index_path.read_text())
    old_digest = metadata["manifest_digest"]
    old_path = blob_root / old_digest.removeprefix("sha256:")
    manifest = json.loads(old_path.read_text())

    mutate(manifest, metadata, blob_root)
    manifest_raw = oci._json_bytes(manifest)
    new_digest = "sha256:" + hashlib.sha256(manifest_raw).hexdigest()
    new_path = blob_root / new_digest.removeprefix("sha256:")
    new_path.write_bytes(manifest_raw)
    new_path.chmod(0o600)
    if new_path != old_path:
        old_path.unlink()

    metadata["manifest_digest"] = new_digest
    manifest_blob = next(
        item for item in metadata["blobs"] if item["digest"] == old_digest
    )
    manifest_blob.update(digest=new_digest, size=len(manifest_raw))
    descriptor = index["manifests"][0]
    descriptor.update(digest=new_digest, size=len(manifest_raw))
    metadata_path.write_bytes(oci._json_bytes(metadata))
    index_path.write_bytes(oci._json_bytes(index))


def test_convert_docker_archive_produces_verified_oci_layout(tmp_path):
    _root, release, info = _converted_release(tmp_path)

    metadata = json.loads((release / "metadata.json").read_text())
    assert metadata == {
        "schema_version": 1,
        "engine_image_ref": "numericaloj-vibehub-runtime:1",
        "engine_image_id": info.engine_image_id,
        "manifest_digest": info.manifest_digest,
        "blobs": [
            {"digest": digest, "size": size} for digest, size in info.blobs
        ],
    }
    assert (release / "blobs" / "sha256" / info.manifest_digest[7:]).is_file()
    assert oci.verify_release(release) == info


def test_verify_release_rejects_unknown_metadata_schema(tmp_path):
    _root, release, _info = _converted_release(tmp_path)
    metadata_path = release / "metadata.json"
    metadata = json.loads(metadata_path.read_text())
    metadata["schema_version"] = 999
    metadata_path.write_bytes(oci._json_bytes(metadata))

    with pytest.raises(oci.OCIExportError, match="metadata 字段集合"):
        oci.verify_release(release)


def test_verify_release_rejects_unreferenced_metadata_blob(tmp_path):
    _root, release, _info = _converted_release(tmp_path)
    metadata_path = release / "metadata.json"
    metadata = json.loads(metadata_path.read_text())
    raw = b"unreferenced OCI blob\n"
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    blob = release / "blobs" / "sha256" / digest.removeprefix("sha256:")
    blob.write_bytes(raw)
    blob.chmod(0o600)
    metadata["blobs"].append({"digest": digest, "size": len(raw)})
    metadata_path.write_bytes(oci._json_bytes(metadata))

    with pytest.raises(oci.OCIExportError, match="未精确覆盖"):
        oci.verify_release(release)


@pytest.mark.parametrize(
    "damage",
    ["config-extra-field", "layer-missing-identity", "duplicate-layer"],
)
def test_verify_release_rejects_noncanonical_manifest_descriptors(tmp_path, damage):
    _root, release, _info = _converted_release(tmp_path)

    def mutate(manifest, _metadata, _blob_root):
        if damage == "config-extra-field":
            manifest["config"]["urls"] = ["https://invalid.example/config"]
        elif damage == "layer-missing-identity":
            manifest["layers"][0].pop("digest")
            manifest["layers"][0].pop("size")
        else:
            manifest["layers"].append(dict(manifest["layers"][0]))

    _rewrite_release_manifest(release, mutate)

    with pytest.raises(oci.OCIExportError, match="config/layers|layer descriptor|重复 layer"):
        oci.verify_release(release)


def test_verify_release_rejects_index_descriptor_extensions(tmp_path):
    _root, release, _info = _converted_release(tmp_path)
    index_path = release / "index.json"
    index = json.loads(index_path.read_text())
    index["manifests"][0]["urls"] = ["https://invalid.example/manifest"]
    index_path.write_bytes(oci._json_bytes(index))

    with pytest.raises(oci.OCIExportError, match="index manifest descriptor"):
        oci.verify_release(release)


def test_verify_release_binds_config_diff_ids_to_ordered_layers(tmp_path):
    _root, release, _info = _converted_release(tmp_path)

    def mutate(manifest, metadata, blob_root):
        old_layer_digest = manifest["layers"][0]["digest"]
        config_digest = metadata["engine_image_id"]
        config_size = next(
            item["size"]
            for item in metadata["blobs"]
            if item["digest"] == config_digest
        )
        manifest["layers"][0].update(
            digest=config_digest,
            size=config_size,
        )
        metadata["blobs"] = [
            item
            for item in metadata["blobs"]
            if item["digest"] != old_layer_digest
        ]
        (blob_root / old_layer_digest.removeprefix("sha256:")).unlink()

    _rewrite_release_manifest(release, mutate)

    with pytest.raises(oci.OCIExportError, match="rootfs.diff_ids"):
        oci.verify_release(release)


def test_convert_rejects_archive_traversal_and_symlinks(tmp_path):
    for kind, name in ((tarfile.REGTYPE, "../escape"), (tarfile.SYMTYPE, "bad-link")):
        archive = tmp_path / f"{kind!r}.tar"
        extra = tarfile.TarInfo(name)
        extra.type = kind
        if kind == tarfile.SYMTYPE:
            extra.linkname = "manifest.json"
        image_id = _docker_archive(archive, extra=extra)
        release = tmp_path / f"release-{kind!r}"
        with pytest.raises(oci.OCIExportError, match="路径逃逸|链接或特殊"):
            oci.convert_docker_archive(
                archive,
                release,
                engine_image_ref="numericaloj-vibehub-runtime:1",
                engine_image_id=image_id,
            )
        assert not release.exists()


def test_convert_rejects_layer_diff_id_mismatch(tmp_path):
    archive = tmp_path / "bad-hash.tar"
    image_id = _docker_archive(archive, diff_id="sha256:" + "0" * 64)
    with pytest.raises(oci.OCIExportError, match="diff-id/hash"):
        oci.convert_docker_archive(
            archive,
            tmp_path / "release",
            engine_image_ref="numericaloj-vibehub-runtime:1",
            engine_image_id=image_id,
        )


def test_current_switch_is_compare_and_swap_and_can_restore_missing(tmp_path):
    root, release, _info = _converted_release(tmp_path)
    target = oci.switch_current(root, release, expected_current="")
    assert target == f"releases/{release.name}"
    assert (root / "current").is_symlink()

    with pytest.raises(oci.OCIExportError, match="发生漂移"):
        oci.switch_current(root, release, expected_current="")
    oci.restore_current(root, candidate_current=target, previous_current="")
    assert not (root / "current").exists()


def test_export_metadata_and_current_match_runtime_named_context_contract(tmp_path):
    root, release, info = _converted_release(tmp_path)
    oci.switch_current(root, release, expected_current="")

    contexts = runtime.DockerCLI(
        base_oci_layout_root=root
    )._base_oci_build_contexts(
        (("numericaloj-vibehub-runtime:1", info.engine_image_id),)
    )

    assert contexts == (
        "numericaloj-vibehub-runtime:1="
        f"oci-layout://{release}@{info.manifest_digest}",
    )


def test_release_prune_keeps_current_and_explicit_previous(tmp_path):
    root, current_release, _current_info = _converted_release(tmp_path)
    current = oci.switch_current(root, current_release, expected_current="")
    releases = root / "releases"
    targets = []
    for marker in ("previous", "obsolete"):
        archive = tmp_path / f"{marker}.tar"
        image_id = _docker_archive(archive, config_marker=marker)
        release = releases / image_id[7:]
        oci.convert_docker_archive(
            archive,
            release,
            engine_image_ref="numericaloj-vibehub-runtime:1",
            engine_image_id=image_id,
        )
        targets.append(f"releases/{release.name}")

    assert oci.prune_releases(root, keep_targets=[targets[0]]) == 1
    assert (root / current).is_dir()
    assert (root / targets[0]).is_dir()
    assert not (root / targets[1]).exists()


def test_export_uses_docker_image_save_and_publishes_by_engine_id(tmp_path):
    archive_fixture = tmp_path / "fixture.tar"
    image_id = _docker_archive(archive_fixture)
    commands = []

    def runner(command, **_kwargs):
        commands.append(command)
        if command[:3] == ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(command, 0, json.dumps({"Id": image_id}), "")
        if command[:3] == ["docker", "image", "save"]:
            Path(command[4]).write_bytes(archive_fixture.read_bytes())
            return subprocess.CompletedProcess(command, 0, "", "")
        raise AssertionError(command)

    root = tmp_path / "layout"
    root.mkdir(mode=0o700)
    info = oci.export_engine_image(
        image="numericaloj-vibehub-runtime:deploy-test",
        engine_image_ref="numericaloj-vibehub-runtime:1",
        output_root=root,
        expected_image_id=image_id,
        command_runner=runner,
    )

    assert info.path == root / "releases" / image_id[7:]
    assert [command[:3] for command in commands].count(
        ["docker", "image", "inspect"]
    ) == 2
    save = next(command for command in commands if command[:3] == ["docker", "image", "save"])
    assert save[-1] == "numericaloj-vibehub-runtime:deploy-test"


def test_offline_probe_uses_exact_oci_context_and_prune(tmp_path):
    _root, release, info = _converted_release(tmp_path)
    commands = []

    def runner(command, **_kwargs):
        commands.append(command)
        if command[:3] == ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(command, 0, info.manifest_digest + "\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    oci.probe_builder(
        builder="numoj-vibehub",
        release=release,
        run_id="deploy-test",
        command_runner=runner,
    )

    build = next(command for command in commands if command[:3] == ["docker", "buildx", "build"])
    context_value = (
        "numericaloj-vibehub-runtime:1="
        f"oci-layout://{release}@{info.manifest_digest}"
    )
    assert ["--build-context", context_value] == build[
        build.index("--build-context") : build.index("--build-context") + 2
    ]
    assert ["--network", "none"] == build[build.index("--network") : build.index("--network") + 2]
    assert "--pull=false" in build
    assert "--load" in build
    assert "--resource" not in build
    prune = next(command for command in commands if command[:3] == ["docker", "buildx", "prune"])
    assert prune[-2:] == ["--max-used-space", "4294967296"]


def test_offline_probe_preserves_bounded_buildx_error(tmp_path):
    _root, release, _info = _converted_release(tmp_path)

    def runner(command, **_kwargs):
        if command[:3] == ["docker", "buildx", "build"]:
            return subprocess.CompletedProcess(
                command,
                125,
                "",
                "unknown flag: --future-option\n" + ("x" * 2000),
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    with pytest.raises(
        oci.OCIExportError,
        match=r"退出码：125.*unknown flag: --future-option",
    ) as exc_info:
        oci.probe_builder(
            builder="numoj-vibehub",
            release=release,
            run_id="deploy-test",
            command_runner=runner,
        )

    assert len(str(exc_info.value)) <= 1100
