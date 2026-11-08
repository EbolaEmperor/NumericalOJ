from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from deploy import export_editor_headers, prepare_editor_toolchain
from backend.oj_modules.editor import toolchain as editor_toolchain
from backend.oj_modules.project_paths import PROJECT_ROOT


def test_default_toolchain_path_uses_stable_project_root():
    assert editor_toolchain.PROJECT_ROOT == PROJECT_ROOT
    assert editor_toolchain.DEFAULT_CURRENT_TOOLCHAIN == (
        PROJECT_ROOT / ".deploy" / "current-editor-toolchain"
    )


def _populate_export(root: Path) -> None:
    files = {
        "usr/include/c++/12/vector": "// vector\n",
        "usr/include/c++/12/backward/.keep": "",
        "usr/include/x86_64-linux-gnu/c++/12/bits/c++config.h": "// config\n",
        "usr/lib/gcc/x86_64-linux-gnu/12/include/stddef.h": "// stddef\n",
        "usr/include/eigen3/Eigen/Eigen": "// Eigen\n",
        "usr/include/eigen3/Eigen/SparseLU": "// SparseLU\n",
        "usr/include/x86_64-linux-gnu/cblas.h": "// cblas\n",
        "usr/include/lapacke.h": "// lapacke\n",
        "opt/mkl/include/mkl.h": "// mkl\n",
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    (root / "opt/library").mkdir(parents=True, exist_ok=True)
    (root / "usr/local/include").mkdir(parents=True, exist_ok=True)
    compiler_search = {
        "schema_version": 1,
        "c": [
            "/usr/lib/gcc/x86_64-linux-gnu/12/include",
            "/usr/local/include",
            "/usr/include/x86_64-linux-gnu",
            "/usr/include",
        ],
        "cpp": [
            "/usr/include/c++/12",
            "/usr/include/x86_64-linux-gnu/c++/12",
            "/usr/include/c++/12/backward",
            "/usr/lib/gcc/x86_64-linux-gnu/12/include",
            "/usr/local/include",
            "/usr/include/x86_64-linux-gnu",
            "/usr/include",
        ],
    }
    (root / editor_toolchain.COMPILER_SEARCH_FILENAME).write_text(
        json.dumps(compiler_search),
        encoding="utf-8",
    )


def _write_manifest(root: Path, *, mode="full") -> dict:
    manifest = editor_toolchain.build_editor_toolchain_manifest(
        root,
        source_image_reference="numericaloj-judger:deploy-test",
        source_image_id="sha256:abc123",
        mode=mode,
    )
    (root / editor_toolchain.MANIFEST_FILENAME).write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    return manifest


def test_manifest_discovers_and_loads_all_official_header_roots(tmp_path):
    root = tmp_path / "toolchain"
    _populate_export(root)
    manifest = _write_manifest(root)

    loaded = editor_toolchain.load_editor_toolchain(root, required=True)

    assert loaded is not None
    assert loaded.root == root.resolve()
    assert loaded.source_image_id == "sha256:abc123"
    assert "usr/include/c++/12" in manifest["cpp_include_paths"]
    assert (
        "usr/include/x86_64-linux-gnu/c++/12"
        in manifest["cpp_include_paths"]
    )
    assert (
        "usr/lib/gcc/x86_64-linux-gnu/12/include"
        in manifest["c_include_paths"]
    )
    assert "usr/include/eigen3" in manifest["cpp_include_paths"]
    assert (
        "usr/include/x86_64-linux-gnu"
        in manifest["c_include_paths"]
    )
    assert "opt/mkl/include" in manifest["c_include_paths"]
    assert {
        path.relative_to(loaded.root).as_posix()
        for path in loaded.required_headers
    } >= {
        "usr/include/c++/12/vector",
        "usr/include/eigen3/Eigen/Eigen",
        "usr/include/eigen3/Eigen/SparseLU",
        "usr/include/x86_64-linux-gnu/cblas.h",
        "usr/include/lapacke.h",
        "opt/mkl/include/mkl.h",
    }


def test_explicit_lite_manifest_loads_without_mkl_and_keeps_other_official_libraries(tmp_path):
    root = tmp_path / "toolchain"
    _populate_export(root)
    shutil.rmtree(root / "opt/mkl")
    manifest = _write_manifest(root, mode="lite")
    loaded = editor_toolchain.load_editor_toolchain(root, required=True)
    assert loaded.mode == "lite" and loaded.has_mkl is False
    assert manifest["libraries"] == {"mkl": False}
    assert "opt/mkl/include" not in manifest["c_include_paths"]
    assert "opt/mkl/include" not in manifest["cpp_include_paths"]
    assert set(manifest["required_headers"]) == {
        "usr/include/c++/12/vector", "usr/include/eigen3/Eigen/Eigen",
        "usr/include/eigen3/Eigen/SparseLU", "usr/include/x86_64-linux-gnu/cblas.h",
        "usr/include/lapacke.h",
    }


def test_full_mode_never_downgrades_when_mkl_is_missing(tmp_path):
    root = tmp_path / "toolchain"
    _populate_export(root)
    shutil.rmtree(root / "opt/mkl")
    with pytest.raises(editor_toolchain.EditorToolchainError, match="MKL"):
        _write_manifest(root)


def test_old_manifest_defaults_to_full_mkl_capability(tmp_path):
    root = tmp_path / "toolchain"
    _populate_export(root)
    manifest = _write_manifest(root)
    manifest.pop("mode")
    manifest.pop("libraries")
    path = root / editor_toolchain.MANIFEST_FILENAME
    path.write_text(json.dumps(manifest))
    loaded = editor_toolchain.load_editor_toolchain(root, required=True)
    assert loaded.mode == "full" and loaded.has_mkl is True
    manifest["required_headers"].remove("opt/mkl/include/mkl.h")
    manifest["c_include_paths"].remove("opt/mkl/include")
    manifest["cpp_include_paths"].remove("opt/mkl/include")
    shutil.rmtree(root / "opt/mkl")
    path.write_text(json.dumps(manifest))
    with pytest.raises(editor_toolchain.EditorToolchainError, match="MKL"):
        editor_toolchain.load_editor_toolchain(root, required=True)


@pytest.mark.parametrize("capability", [None, "false", 0, {"mkl": "false"}, {"mkl": False}, {"mkl": True, "unknown": True}])
def test_full_manifest_rejects_invalid_or_disabled_mkl_capabilities(tmp_path, capability):
    root = tmp_path / "toolchain"
    _populate_export(root)
    manifest = _write_manifest(root)
    manifest["libraries"] = capability
    (root / editor_toolchain.MANIFEST_FILENAME).write_text(json.dumps(manifest))
    with pytest.raises(editor_toolchain.EditorToolchainError, match="能力无效"):
        editor_toolchain.load_editor_toolchain(root, required=True)


@pytest.mark.parametrize("header,label", [("usr/include/eigen3/Eigen/SparseLU", "SparseLU"),
                                         ("usr/include/x86_64-linux-gnu/cblas.h", "CBLAS"),
                                         ("usr/include/lapacke.h", "LAPACKE")])
def test_lite_still_requires_non_mkl_official_headers(tmp_path, header, label):
    root = tmp_path / "toolchain"
    _populate_export(root)
    shutil.rmtree(root / "opt/mkl")
    (root / header).unlink()
    with pytest.raises(editor_toolchain.EditorToolchainError, match=label):
        _write_manifest(root, mode="lite")


def test_lite_with_mkl_keeps_the_capability_enabled(tmp_path):
    root = tmp_path / "toolchain"
    _populate_export(root)
    manifest = _write_manifest(root, mode="lite")
    assert editor_toolchain.load_editor_toolchain(root, required=True).has_mkl is True
    manifest["libraries"]["mkl"] = False
    (root / editor_toolchain.MANIFEST_FILENAME).write_text(json.dumps(manifest))
    with pytest.raises(editor_toolchain.EditorToolchainError, match="包含 MKL 导出"):
        editor_toolchain.load_editor_toolchain(root, required=True)


def test_manifest_rejects_include_path_escape(tmp_path):
    root = tmp_path / "toolchain"
    _populate_export(root)
    manifest = _write_manifest(root)
    manifest["cpp_include_paths"] = ["../outside"]
    (root / editor_toolchain.MANIFEST_FILENAME).write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    with pytest.raises(
        editor_toolchain.EditorToolchainError,
        match="超出受管工具链",
    ):
        editor_toolchain.load_editor_toolchain(root, required=True)


def test_default_managed_path_must_be_symlink(monkeypatch, tmp_path):
    direct_root = tmp_path / "current-editor-toolchain"
    _populate_export(direct_root)
    _write_manifest(direct_root)
    monkeypatch.setattr(
        editor_toolchain,
        "DEFAULT_CURRENT_TOOLCHAIN",
        direct_root,
    )

    with pytest.raises(
        editor_toolchain.EditorToolchainError,
        match="符号链接",
    ):
        editor_toolchain.load_editor_toolchain()


def test_prepare_toolchain_replaces_only_inactive_slot_atomically(
    monkeypatch,
    tmp_path,
):
    output = tmp_path / "editor-toolchains" / "slot-a"
    output.mkdir(parents=True)
    (output / "old-marker").write_text("old", encoding="utf-8")
    monkeypatch.setattr(
        prepare_editor_toolchain,
        "_image_id",
        lambda image: "sha256:new-image",
    )

    def fake_export(image, staging_root, *, mode="full"):
        assert image == "numericaloj-judger:deploy-test"
        _populate_export(staging_root)

    monkeypatch.setattr(
        prepare_editor_toolchain,
        "_export_headers",
        fake_export,
    )

    prepare_editor_toolchain.prepare_editor_toolchain(
        "numericaloj-judger:deploy-test",
        output,
    )

    loaded = editor_toolchain.load_editor_toolchain(output, required=True)
    assert loaded is not None
    assert loaded.source_image_id == "sha256:new-image"
    assert not (output / "old-marker").exists()
    assert not list(output.parent.glob(".slot-a-old-*"))
    assert not list(output.parent.glob(".slot-a-preparing-*"))


def test_prepare_explicit_lite_passes_mode_to_exporter_and_manifest(monkeypatch, tmp_path):
    output = tmp_path / "editor-toolchains/slot-a"
    monkeypatch.setattr(prepare_editor_toolchain, "_image_id", lambda _: "sha256:lite-image")
    modes = []
    def export(_image, staging, *, mode):
        modes.append(mode)
        _populate_export(staging)
        shutil.rmtree(staging / "opt/mkl")
    monkeypatch.setattr(prepare_editor_toolchain, "_export_headers", export)
    prepare_editor_toolchain.prepare_editor_toolchain("numericaloj-judger:deploy-lite", output, mode="lite")
    assert modes == ["lite"]
    loaded = editor_toolchain.load_editor_toolchain(output, required=True)
    assert loaded.mode == "lite" and loaded.has_mkl is False


def test_prepare_toolchain_refuses_current_slot(monkeypatch, tmp_path):
    toolchain_root = tmp_path / "editor-toolchains"
    output = toolchain_root / "slot-a"
    output.mkdir(parents=True)
    (tmp_path / "current-editor-toolchain").symlink_to(
        Path("editor-toolchains") / "slot-a"
    )
    monkeypatch.setattr(
        prepare_editor_toolchain,
        "_image_id",
        lambda image: pytest.fail("active slot must be rejected before Docker"),
    )

    with pytest.raises(
        prepare_editor_toolchain.EditorToolchainPreparationError,
        match="正在使用",
    ):
        prepare_editor_toolchain.prepare_editor_toolchain(
            "numericaloj-judger:deploy-test",
            output,
        )


def test_prepare_toolchain_rejects_option_like_image_reference(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(
        prepare_editor_toolchain,
        "_image_id",
        lambda image: pytest.fail("invalid image must not reach Docker"),
    )

    with pytest.raises(
        prepare_editor_toolchain.EditorToolchainPreparationError,
        match="镜像引用无效",
    ):
        prepare_editor_toolchain.prepare_editor_toolchain(
            "--privileged",
            tmp_path / "editor-toolchains" / "slot-a",
        )


@pytest.mark.parametrize("mode", ["full", "lite"])
def test_export_container_is_locked_down_and_always_removed(
    monkeypatch,
    tmp_path,
    mode,
):
    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if command[:4] == ["docker", "container", "rm", "--force"]:
            return subprocess.CompletedProcess(
                command,
                1,
                "",
                "Error: No such container",
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(prepare_editor_toolchain, "_run", fake_run)

    prepare_editor_toolchain._export_headers(
        "numericaloj-judger:deploy-test",
        tmp_path,
        mode=mode,
    )

    run_command = commands[0]
    assert run_command[:2] == ["docker", "run"]
    for required in (
        "--rm",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=64",
    ):
        assert required in run_command
    assert "--entrypoint=/usr/bin/python3" in run_command
    assert "/opt/numericaloj-export-editor-headers.py" in run_command
    assert run_command[-4:] == ["--output", "/export", "--mode", mode]
    mounts = [
        run_command[index + 1]
        for index, argument in enumerate(run_command)
        if argument == "--mount"
    ]
    assert any(
        mount.startswith("type=bind,")
        and "dst=/export" in mount
        and not mount.endswith(",rw")
        for mount in mounts
    )
    assert any(
        "dst=/opt/numericaloj-export-editor-headers.py" in mount
        and mount.endswith(",readonly")
        for mount in mounts
    )
    assert commands[-1][:4] == ["docker", "container", "rm", "--force"]


def test_export_failure_does_not_hide_unknown_container_cleanup(
    monkeypatch,
    tmp_path,
):
    def fake_run(command, **kwargs):
        if command[:4] == ["docker", "container", "rm", "--force"]:
            return subprocess.CompletedProcess(
                command,
                125,
                "",
                "Docker daemon unavailable",
            )
        return subprocess.CompletedProcess(command, 1, "", "")

    monkeypatch.setattr(prepare_editor_toolchain, "_run", fake_run)

    with pytest.raises(
        prepare_editor_toolchain.EditorToolchainPreparationError,
        match="无法确认临时容器已删除",
    ):
        prepare_editor_toolchain._export_headers(
            "numericaloj-judger:deploy-test",
            tmp_path,
        )


def test_export_validation_rejects_symlinks(tmp_path):
    (tmp_path / "real.h").write_text("// real\n", encoding="utf-8")
    (tmp_path / "link.h").symlink_to(tmp_path / "real.h")

    with pytest.raises(
        prepare_editor_toolchain.EditorToolchainPreparationError,
        match="符号链接",
    ):
        prepare_editor_toolchain._validate_export_tree(tmp_path)


def test_image_export_copy_rejects_symlink_escape(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside.h"
    outside.write_text("secret", encoding="utf-8")
    (source / "escape.h").symlink_to(outside)
    destination = tmp_path / "destination"

    with pytest.raises(export_editor_headers.ExportError, match="escapes"):
        export_editor_headers._copy_tree(
            source,
            destination,
            allowed_roots=(source.resolve(),),
            budget=export_editor_headers._Budget(),
            active_directories=set(),
        )


@pytest.mark.parametrize("mode", ["full", "lite"])
def test_export_only_explicit_lite_skips_completely_absent_mkl(monkeypatch, tmp_path, mode):
    library = tmp_path / "library"
    library.mkdir()
    (library / "official.h").write_text("// shared")
    mkl = tmp_path / "mkl/include"
    monkeypatch.setattr(export_editor_headers, "_OFFICIAL_INCLUDE_ROOTS", (
        (mkl, "opt/mkl/include", tmp_path / "intel/mkl"),
        (library, "opt/library", library),
    ))
    output = tmp_path / "export"
    output.mkdir()
    if mode == "full":
        with pytest.raises(FileNotFoundError):
            export_editor_headers._copy_official_roots(output, mode=mode, budget=export_editor_headers._Budget())
    else:
        export_editor_headers._copy_official_roots(output, mode=mode, budget=export_editor_headers._Budget())
        assert (output / "opt/library/official.h").read_text() == "// shared"
        assert not (output / "opt/mkl").exists()


def test_lite_export_does_not_hide_broken_mkl_installation(monkeypatch, tmp_path):
    mkl = tmp_path / "mkl"
    mkl.symlink_to(tmp_path / "missing-installation")
    monkeypatch.setattr(export_editor_headers, "_OFFICIAL_INCLUDE_ROOTS", (
        (mkl / "include", "opt/mkl/include", tmp_path / "intel/mkl"),
    ))
    with pytest.raises(FileNotFoundError):
        export_editor_headers._copy_official_roots(tmp_path, mode="lite", budget=export_editor_headers._Budget())
