#!/usr/bin/env python3
"""Export the official C/C++ headers from a candidate judge image.

The destination is always one inactive ``slot-a``/``slot-b`` directory.  A
locked-down temporary container dereferences image symlinks while copying into
a private staging directory; the host then rejects links, special files, path
escapes, and unexpectedly large exports before publishing the slot.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oj_modules.editor.toolchain import (  # noqa: E402
    MANIFEST_FILENAME,
    EditorToolchainError,
    build_editor_toolchain_manifest,
    load_editor_toolchain,
)


MAX_EXPORT_FILES = 200_000
MAX_EXPORT_BYTES = 2 * 1024 * 1024 * 1024
_SAFE_IMAGE_REFERENCE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")


class EditorToolchainPreparationError(RuntimeError):
    """The candidate image could not produce a safe complete header export."""


def _run(
    command: list[str],
    *,
    timeout: float,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        capture_output=capture_output,
        text=True,
        timeout=timeout,
    )


def _image_id(image: str) -> str:
    result = _run(
        ["docker", "image", "inspect", "--format={{.Id}}", image],
        timeout=30,
        capture_output=True,
    )
    image_id = result.stdout.strip()
    if result.returncode != 0 or not image_id.startswith("sha256:"):
        detail = result.stderr.strip() or image
        raise EditorToolchainPreparationError(
            f"无法读取候选判题镜像 ID：{detail}"
        )
    return image_id


def _remove_export_container(container_name: str) -> None:
    result = _run(
        ["docker", "container", "rm", "--force", container_name],
        timeout=30,
        capture_output=True,
    )
    if result.returncode == 0:
        return
    detail = f"{result.stdout}\n{result.stderr}".lower()
    if "no such container" in detail:
        return
    raise EditorToolchainPreparationError(
        f"无法确认头文件导出容器已删除：{result.stderr.strip()}"
    )


def _export_headers(image: str, staging_root: Path) -> None:
    mount_source = str(staging_root.resolve(strict=True))
    exporter_source = str(
        Path(__file__).with_name("export_editor_headers.py").resolve(strict=True)
    )
    if "," in mount_source or "," in exporter_source:
        raise EditorToolchainPreparationError(
            "受管工具链路径不能包含 Docker mount 分隔符"
        )
    container_name = (
        f"numericaloj-editor-toolchain-{os.getpid()}-{uuid.uuid4().hex[:12]}"
    )
    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=64",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--mount",
        f"type=bind,src={mount_source},dst=/export",
        "--mount",
        (
            f"type=bind,src={exporter_source},"
            "dst=/opt/numericaloj-export-editor-headers.py,readonly"
        ),
        "--entrypoint=/usr/bin/python3",
        image,
        "/opt/numericaloj-export-editor-headers.py",
        "--output",
        "/export",
    ]
    failure: BaseException | None = None
    try:
        result = _run(command, timeout=15 * 60)
        if result.returncode != 0:
            raise EditorToolchainPreparationError(
                f"候选判题镜像头文件导出失败（退出码 {result.returncode}）"
            )
    except BaseException as exc:
        failure = exc
        raise
    finally:
        try:
            _remove_export_container(container_name)
        except BaseException as cleanup_error:
            if failure is not None:
                raise EditorToolchainPreparationError(
                    "头文件导出失败，且无法确认临时容器已删除"
                ) from cleanup_error
            raise


def _validate_export_tree(root: Path) -> None:
    file_count = 0
    total_bytes = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            children = list(os.scandir(directory))
        except OSError as exc:
            raise EditorToolchainPreparationError(
                f"无法检查头文件导出目录：{directory}"
            ) from exc
        for child in children:
            try:
                child_stat = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise EditorToolchainPreparationError(
                    f"无法检查头文件导出条目：{child.path}"
                ) from exc
            mode = child_stat.st_mode
            if stat.S_ISLNK(mode):
                raise EditorToolchainPreparationError(
                    f"头文件导出不得保留符号链接：{child.path}"
                )
            if stat.S_ISDIR(mode):
                pending.append(Path(child.path))
                continue
            if not stat.S_ISREG(mode) or child_stat.st_nlink != 1:
                raise EditorToolchainPreparationError(
                    f"头文件导出包含特殊文件或硬链接：{child.path}"
                )
            file_count += 1
            total_bytes += child_stat.st_size
            if file_count > MAX_EXPORT_FILES or total_bytes > MAX_EXPORT_BYTES:
                raise EditorToolchainPreparationError(
                    "候选判题镜像头文件导出超出安全上限"
                )


def _safe_remove_slot(path: Path) -> None:
    if not path.exists():
        if path.is_symlink():
            raise EditorToolchainPreparationError(
                f"拒绝删除符号链接工具链槽位：{path}"
            )
        return
    mode = path.lstat().st_mode
    if not stat.S_ISDIR(mode):
        raise EditorToolchainPreparationError(
            f"工具链槽位不是受管目录：{path}"
        )
    shutil.rmtree(path)


def _publish_slot(staging_root: Path, output: Path) -> None:
    old_slot = output.parent / f".{output.name}-old-{uuid.uuid4().hex}"
    had_previous = output.exists()
    if output.is_symlink():
        raise EditorToolchainPreparationError(
            f"拒绝替换符号链接工具链槽位：{output}"
        )
    if had_previous:
        if not output.is_dir():
            raise EditorToolchainPreparationError(
                f"工具链槽位不是目录：{output}"
            )
        os.replace(output, old_slot)
    try:
        os.replace(staging_root, output)
    except BaseException:
        if had_previous and old_slot.exists() and not output.exists():
            os.replace(old_slot, output)
        raise
    if old_slot.exists():
        _safe_remove_slot(old_slot)


def _assert_inactive_slot(output: Path) -> None:
    current_link = output.parent.parent / "current-editor-toolchain"
    if not current_link.exists() and not current_link.is_symlink():
        return
    if not current_link.is_symlink():
        raise EditorToolchainPreparationError(
            "current-editor-toolchain 必须是受管符号链接"
        )
    try:
        current_target = current_link.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise EditorToolchainPreparationError(
            "current-editor-toolchain 已损坏，拒绝覆盖任何槽位"
        ) from exc
    if current_target == output.resolve(strict=False):
        raise EditorToolchainPreparationError(
            f"拒绝覆盖正在使用的编辑器工具链槽位：{output.name}"
        )


def prepare_editor_toolchain(image: str, output: Path) -> None:
    if not _SAFE_IMAGE_REFERENCE.fullmatch(image):
        raise EditorToolchainPreparationError("候选判题镜像引用无效")
    if output.name not in {"slot-a", "slot-b"}:
        raise EditorToolchainPreparationError(
            "受管工具链输出必须是 slot-a 或 slot-b"
        )
    output_parent = output.parent
    output_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if output_parent.is_symlink() or not output_parent.is_dir():
        raise EditorToolchainPreparationError(
            "受管工具链根必须是真实目录"
        )
    _assert_inactive_slot(output)

    image_id = _image_id(image)
    staging_root = Path(
        tempfile.mkdtemp(
            prefix=f".{output.name}-preparing-",
            dir=output_parent,
        )
    )
    try:
        _export_headers(image, staging_root)
        _validate_export_tree(staging_root)
        manifest = build_editor_toolchain_manifest(
            staging_root,
            source_image_reference=image,
            source_image_id=image_id,
        )
        manifest_path = staging_root / MANIFEST_FILENAME
        with manifest_path.open("x", encoding="utf-8") as stream:
            json.dump(
                manifest,
                stream,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        load_editor_toolchain(staging_root, required=True)
        _publish_slot(staging_root, output)
    except (OSError, subprocess.SubprocessError, EditorToolchainError) as exc:
        raise EditorToolchainPreparationError(str(exc)) from exc
    finally:
        if staging_root.exists() and not staging_root.is_symlink():
            shutil.rmtree(staging_root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="从候选判题镜像准备 clangd 官方头文件工具链"
    )
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        prepare_editor_toolchain(args.image, args.output)
    except (
        EditorToolchainPreparationError,
        OSError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"[editor-toolchain] {exc}", file=sys.stderr)
        return 1
    print(f"editor toolchain ready: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
