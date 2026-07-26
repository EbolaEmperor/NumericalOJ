#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""沙箱判题核心（Docker 容器隔离）。

所有用户代码在 Docker 容器中执行，实现进程/文件系统/网络完全隔离。
不再使用 RLIMIT_* 或宿主机直接 subprocess 执行。

API:
  - run_single(language, data) -> result_dict
  - batch_evaluate_stream(language, data) -> 生成器，逐个 yield 事件 dict
  - batch_evaluate(language, data) -> {compile_result, test_results}
"""

import os
import platform
import re
import shutil
import stat
import time
import uuid

from oj_modules.docker_sandbox import run_case_in_container, run_in_container
from oj_modules.repository.workspace import (
    REPOSITORY_CONTAINER_ROOT,
    InvalidRepositoryPath,
    materialize_repository_tree,
    normalize_repository_relative_path,
)


# ========== OJ 根目录 / 头文件库路径 ==========
def get_oj_root_path():
    """获取 OJ 系统根目录：环境变量 OJ_ROOT_PATH > 基于本文件位置（oj_modules/ 的上一级）> /opt/oj。"""
    oj_root = os.environ.get("OJ_ROOT_PATH")
    if oj_root and os.path.exists(oj_root):
        return oj_root

    current_dir = os.path.dirname(os.path.abspath(__file__))
    oj_root = os.path.dirname(current_dir)
    if os.path.exists(oj_root):
        return oj_root

    return "/opt/oj"


OJ_ROOT_PATH = get_oj_root_path()

JUDGER_RUN_ROOT = (
    str(os.environ.get("JUDGER_RUN_ROOT") or "").strip()
    or os.path.join(OJ_ROOT_PATH, "judger")
)


# ========== 通用工具 ==========
SAFE_SID_PATTERN = re.compile(r'^[A-Za-z0-9_\-\.]+$')
IMAGE_FILE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}
OUTPUT_ARTIFACT_MAX_BYTES = 32 * 1024 * 1024
OUTPUT_TEXT_MAX_BYTES = 1024 * 1024


# ========== C/C++ 编译命令 ==========
# 数值库题（题面所谓"评测环境已配置好编译链接参数"）依赖 Intel MKL。镜像内通过
# /opt/mkl/{include,lib} 软链统一暴露 MKL（屏蔽 oneAPI 版本目录差异，见 Dockerfile）。
# Sequential / LP64 链接组合，与 Intel Link Line Advisor 推荐的 gcc 选项一致；MKL 同时
# 提供 Fortran 原生符号（dsyev_ 等）、CBLAS（cblas_*）、LAPACKE（LAPACKE_*），因此用
# <mkl.h> 或通用 <cblas.h>/<lapacke.h> 头的解法都能解析符号。否则数值库题必 CE。
# -Wl,--no-as-needed 确保即使目标文件未直接引用也保留这些库；-ldl/-lpthread/-lm 兜底。
MKL_INCLUDE_DIR = "/opt/mkl/include"
MKL_LIB_DIR = "/opt/mkl/lib"
EIGEN_INCLUDE_DIR = "/usr/include/eigen3"
MKL_COMPILE_FLAGS = ["-I", MKL_INCLUDE_DIR]
MKL_LINK_FLAGS = [
    "-L", MKL_LIB_DIR,
    f"-Wl,-rpath,{MKL_LIB_DIR}",
    "-Wl,--no-as-needed",
    "-lmkl_intel_lp64", "-lmkl_sequential", "-lmkl_core",
    "-lpthread", "-ldl", "-lm",
]
OPENBLAS_LINK_FLAGS = [
    "-lopenblas", "-llapacke", "-llapack", "-lblas", "-lm",
]


def _config_value(name, default=None):
    env_value = os.environ.get(name)
    if env_value is not None and str(env_value).strip() != "":
        return env_value
    try:
        import config as _cfg
    except ImportError:
        return default
    return getattr(_cfg, name, default)


def _truthy_config_value(value):
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    return None


def _timeout_kill_after_arg():
    """coreutils timeout 的强制回收宽限。

    Octave/gnuplot 收到 TERM 后可能保存 workspace 或清理子进程；没有 -k 时，
    timeout 会一直等它退出，导致 TLE 记录时间远大于题目限制。
    """
    raw_value = _config_value("JUDGER_TIMEOUT_KILL_AFTER_SEC", 1.0)
    try:
        value = max(0.1, float(raw_value))
    except (TypeError, ValueError):
        value = 1.0
    return f"{value:g}s"


def _timeout_cmd(limit_sec, *cmd):
    return ["timeout", "-k", _timeout_kill_after_arg(), f"{limit_sec}s", *cmd]


def _octave_plot_warmup_enabled():
    raw_value = _config_value("JUDGER_OCTAVE_PLOT_WARMUP", True)
    parsed = _truthy_config_value(raw_value)
    return True if parsed is None else parsed


def _warmup_octave_plot_in_container(run_dir):
    if not _octave_plot_warmup_enabled():
        return
    warmup_code = (
        'graphics_toolkit("gnuplot"); '
        'figure("visible", "off"); '
        'plot([0 1], [0 1]); '
        'print("-dpng", "/tmp/numoj_plot_warmup.png"); '
        'close all;'
    )
    try:
        run_in_container(
            _timeout_cmd(8, "octave", "--quiet", "--eval", warmup_code),
            run_dir=run_dir,
            timeout_sec=12,
        )
    except Exception:
        pass


def _source_ext_for_language(language):
    lang = str(language or "").strip().lower()
    if lang == "cpp":
        return ".cpp"
    if lang == "c":
        return ".c"
    if lang in ("python", "py"):
        return ".py"
    return ".m"


def _write_source_debug_artifacts(run_dir, data, language):
    """保留调试用源码：原始提交、checker、实际编译/执行源码。"""
    ext = _source_ext_for_language(language)
    artifacts = (
        (f"submitted{ext}", data.get("submittedCode")),
        (f"checker{ext}", data.get("checkerCode")),
    )
    for filename, content in artifacts:
        if content is None:
            continue
        text = content if isinstance(content, str) else str(content)
        try:
            _write_text_file_exclusive(run_dir, filename, text)
        except Exception:
            pass


def _target_machine_arch():
    raw = str(_config_value("JUDGER_TARGET_ARCH", "") or "").strip().lower()
    if raw:
        return raw
    return str(platform.machine() or "").strip().lower()


def _is_x86_64_target():
    return _target_machine_arch() in ("x86_64", "amd64")


def _mkl_compile_flags():
    flags = []
    if _is_x86_64_target():
        flags.append("-m64")
    flags.extend(MKL_COMPILE_FLAGS)
    return flags


def _numeric_backend():
    """返回 C/C++ 数值库后端：mkl / openblas / none。

    生产默认仍是 MKL；本机 lite 镜像名包含 judger-lite 时自动改用
    OpenBLAS/LAPACKE，避免 lite 镜像因为没有 /opt/mkl 而所有 C/C++ 编译失败。
    JUDGER_NUMERIC_BACKEND 可显式关闭数值库；但 judger-lite 镜像没有 MKL，
    因此不会允许显式切回 MKL。
    """
    image = str(_config_value("JUDGER_DOCKER_IMAGE", "numericaloj-judger:latest") or "").lower()
    raw_backend = str(_config_value("JUDGER_NUMERIC_BACKEND", "") or "").strip().lower()
    if raw_backend == "none":
        return "none"
    if "judger-lite" in image:
        return "openblas"
    if raw_backend in ("mkl", "openblas"):
        return raw_backend

    legacy_mkl = _config_value("JUDGER_ENABLE_MKL", None)
    if legacy_mkl is not None:
        parsed = _truthy_config_value(legacy_mkl)
        if parsed is not None:
            return "mkl" if parsed else "openblas"

    if not _is_x86_64_target():
        return "openblas"

    return "mkl"


def build_compile_cmd(
    language,
    compile_timeout_sec=30,
    *,
    source_path=None,
):
    """构造 C/C++ 容器内编译命令。"""
    if language == "cpp":
        cmd = _timeout_cmd(compile_timeout_sec, "g++", "-O2", "-pipe", "-s", "-std=c++20")
        src = source_path or "main.cpp"
    else:
        cmd = _timeout_cmd(compile_timeout_sec, "gcc", "-O2", "-pipe", "-s", "-std=c11")
        src = source_path or "main.c"
    cmd.extend(["-I", REPOSITORY_CONTAINER_ROOT, "-I", "/opt/library"])
    if language == "cpp":
        # libeigen3-dev installs headers below /usr/include/eigen3.  Make the
        # documented ``#include <Eigen/...>`` form part of the real judge
        # contract, matching the managed clangd toolchain.
        cmd.extend(["-I", EIGEN_INCLUDE_DIR])
    backend = _numeric_backend()
    if backend == "mkl":
        cmd.extend(_mkl_compile_flags())
    cmd.extend([src, "-o", "a.out"])
    if backend == "mkl":
        cmd.extend(MKL_LINK_FLAGS)
    elif backend == "openblas":
        cmd.extend(OPENBLAS_LINK_FLAGS)
    return cmd


def sanitize_sid(sid: str) -> str:
    value = str(sid or "")
    if (
        not value
        or value in {".", "..", "submission_archive"}
        or value.startswith(".")
        or len(value.encode("utf-8")) > 255
        or not SAFE_SID_PATTERN.fullmatch(value)
    ):
        return f"run_{int(time.time()*1000)}_{uuid.uuid4().hex}"
    return value


def run_dir_for(sid: str) -> str:
    """返回某 sid 对应的运行目录绝对路径（不创建）。"""
    return os.path.join(JUDGER_RUN_ROOT, sanitize_sid(sid))


def _open_plain_directory(path: str) -> int:
    """打开真实目录且拒绝最终路径分量为符号链接。"""
    return os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )


def _open_safe_regular_artifact_fd(
    path: str,
    *,
    max_bytes: int = OUTPUT_ARTIFACT_MAX_BYTES,
) -> int:
    """打开宿主侧产物且固定父目录/最终 inode，不接受 symlink、FIFO 或超大文件。"""
    absolute_path = os.path.abspath(os.fspath(path))
    parent_fd = _open_plain_directory(os.path.dirname(absolute_path))
    try:
        fd = os.open(
            _validate_leaf_name(os.path.basename(absolute_path)),
            os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
    finally:
        os.close(parent_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("判题产物不是普通文件")
        if int(info.st_uid) != int(os.geteuid()) or int(info.st_nlink) != 1:
            raise OSError("判题产物不是宿主创建的独立 inode")
        if stat.S_IMODE(info.st_mode) & 0o022:
            raise OSError("判题产物仍可被非宿主用户修改")
        if int(info.st_size) < 0 or int(info.st_size) > int(max_bytes):
            raise OSError("判题产物大小超限")
        return fd
    except Exception:
        os.close(fd)
        raise


def is_safe_regular_artifact(path: str) -> bool:
    try:
        fd = _open_safe_regular_artifact_fd(path)
    except Exception:
        return False
    os.close(fd)
    return True


def read_safe_regular_artifact(
    path: str,
    *,
    max_bytes: int = OUTPUT_ARTIFACT_MAX_BYTES,
) -> bytes:
    fd = _open_safe_regular_artifact_fd(path, max_bytes=max_bytes)
    try:
        chunks = []
        remaining = int(max_bytes) + 1
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > int(max_bytes):
            raise OSError("判题产物读取时增长并超过大小上限")
        return data
    finally:
        os.close(fd)


def open_safe_regular_artifact(
    path: str,
    *,
    max_bytes: int = OUTPUT_ARTIFACT_MAX_BYTES,
):
    """返回由调用方关闭的二进制文件对象，供 Flask ``send_file`` 安全流式发送。"""
    fd = _open_safe_regular_artifact_fd(path, max_bytes=max_bytes)
    return os.fdopen(fd, "rb")


def _open_run_root() -> int:
    os.makedirs(JUDGER_RUN_ROOT, mode=0o700, exist_ok=True)
    try:
        info = os.lstat(JUDGER_RUN_ROOT)
    except OSError as exc:
        raise RuntimeError("判题运行根不可用") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError("判题运行根必须是真实目录")
    try:
        return _open_plain_directory(JUDGER_RUN_ROOT)
    except OSError as exc:
        raise RuntimeError("无法安全打开判题运行根") from exc


def _validate_leaf_name(name: str) -> str:
    value = str(name or "")
    if (
        not value
        or value in {".", ".."}
        or "\x00" in value
        or len(value.encode("utf-8")) > 255
        or os.path.basename(value) != value
    ):
        raise ValueError("判题工作文件名必须是安全的单级名称")
    return value


def _remove_entry_at(parent_fd: int, name: str) -> None:
    """在已打开的可信父目录中删除一个条目，绝不跟随符号链接。"""
    safe_name = _validate_leaf_name(name)
    try:
        info = os.stat(safe_name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
        if not shutil.rmtree.avoids_symlink_attacks:
            raise RuntimeError("当前 Python 不支持抗符号链接攻击的目录清理")
        shutil.rmtree(safe_name, dir_fd=parent_fd)
        return
    os.unlink(safe_name, dir_fd=parent_fd)


def _create_directory_at(parent_fd: int, name: str, *, mode: int) -> int:
    safe_name = _validate_leaf_name(name)
    os.mkdir(safe_name, mode=0o700, dir_fd=parent_fd)
    directory_fd = os.open(
        safe_name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=parent_fd,
    )
    try:
        os.fchmod(directory_fd, int(mode))
    except Exception:
        os.close(directory_fd)
        _remove_entry_at(parent_fd, safe_name)
        raise
    return directory_fd


def _prepare_run_dir(sid: str) -> str:
    """为每个 attempt 创建宿主私有的公开产物目录。"""
    safe_sid = sanitize_sid(sid)
    root_fd = _open_run_root()
    try:
        # 旧实现曾把此目录 rw 挂给用户容器；即便升级后也必须先安全清掉旧 inode。
        _remove_entry_at(root_fd, safe_sid)
        run_fd = _create_directory_at(root_fd, safe_sid, mode=0o700)
        os.close(run_fd)
    finally:
        os.close(root_fd)
    return os.path.join(JUDGER_RUN_ROOT, safe_sid)


def _prepare_execution_workspace(artifact_dir: str) -> str:
    """创建只含源码/仓库/可执行文件的只读容器基目录。

    公开图片写入其父级 ``artifact_dir``，永远不会被后续 case 挂载。
    """
    run_fd = _open_plain_directory(artifact_dir)
    try:
        _remove_entry_at(run_fd, "workspace")
        workspace_fd = _create_directory_at(
            run_fd,
            "workspace",
            mode=0o755,
        )
        os.close(workspace_fd)
    finally:
        os.close(run_fd)
    return os.path.join(artifact_dir, "workspace")


def _write_text_file_exclusive(directory: str, filename: str, content) -> None:
    """通过 dirfd 独占创建 UTF-8 文本，拒绝跟随容器遗留链接。"""
    safe_name = _validate_leaf_name(filename)
    data = (
        content if isinstance(content, str) else str(content or "")
    ).encode("utf-8")
    directory_fd = _open_plain_directory(directory)
    try:
        fd = os.open(
            safe_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o644,
            dir_fd=directory_fd,
        )
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)


def sanitize_output_image_filename(filename: str) -> str:
    raw = str(filename or "").strip().replace("\\", "/")
    if "/" in raw:
        raw = raw.rsplit("/", 1)[-1].strip()
    if not raw:
        raw = "output.png"
    return raw[:255] or "output.png"


def _wait_for_output_file(path: str, attempts: int = 20, delay_seconds: float = 0.05) -> bool:
    """Wait briefly for Docker bind-mount writes to become visible on the host."""
    for _ in range(max(1, attempts)):
        try:
            info = os.lstat(path)
        except OSError:
            info = None
        if info is not None and stat.S_ISREG(info.st_mode):
            return True
        time.sleep(delay_seconds)
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def _copy_regular_artifact_atomic(
    source_dir: str,
    target_dir: str,
    source_name: str,
    target_name: str,
    *,
    target_mode: int = 0o644,
    max_bytes: int = OUTPUT_ARTIFACT_MAX_BYTES,
) -> None:
    """把容器产物复制为宿主新 inode；源/目标都不允许跟随链接。"""
    safe_source = _validate_leaf_name(source_name)
    safe_target = _validate_leaf_name(target_name)
    source_directory_fd = _open_plain_directory(source_dir)
    target_directory_fd = _open_plain_directory(target_dir)
    temporary_name = f".artifact-{uuid.uuid4().hex}.tmp"
    temporary_created = False
    try:
        source_fd = os.open(
            safe_source,
            os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=source_directory_fd,
        )
        try:
            source_info = os.fstat(source_fd)
            if not stat.S_ISREG(source_info.st_mode):
                raise OSError("容器产物不是普通文件")
            if int(source_info.st_size) < 0 or int(source_info.st_size) > int(max_bytes):
                raise OSError("容器产物大小超限")
            target_fd = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                0o600,
                dir_fd=target_directory_fd,
            )
            temporary_created = True
            try:
                total_written = 0
                while True:
                    chunk = os.read(source_fd, 1024 * 1024)
                    if not chunk:
                        break
                    total_written += len(chunk)
                    if total_written > int(max_bytes):
                        raise OSError("容器产物读取时增长并超过大小上限")
                    view = memoryview(chunk)
                    while view:
                        written = os.write(target_fd, view)
                        view = view[written:]
                os.fchmod(target_fd, int(target_mode))
                os.fsync(target_fd)
            finally:
                os.close(target_fd)
        finally:
            os.close(source_fd)

        os.replace(
            temporary_name,
            safe_target,
            src_dir_fd=target_directory_fd,
            dst_dir_fd=target_directory_fd,
        )
        os.fsync(target_directory_fd)
        temporary_created = False
        if (
            os.path.abspath(source_dir) != os.path.abspath(target_dir)
            or safe_source != safe_target
        ):
            try:
                os.unlink(safe_source, dir_fd=source_directory_fd)
            except OSError:
                pass
    finally:
        if temporary_created:
            try:
                os.unlink(temporary_name, dir_fd=target_directory_fd)
            except OSError:
                pass
        os.close(target_directory_fd)
        os.close(source_directory_fd)


def _adopt_compiled_executable(run_dir: str) -> None:
    """把 linker 产物换成宿主拥有的只读可执行 inode，阻断跨 case 篡改。"""
    _copy_regular_artifact_atomic(
        run_dir,
        run_dir,
        "a.out",
        "a.out",
        target_mode=0o555,
        max_bytes=OUTPUT_ARTIFACT_MAX_BYTES,
    )


def _publish_exported_artifact(
    target_dir: str,
    target_name: str,
    content: bytes,
    *,
    target_mode: int = 0o644,
    max_bytes: int = OUTPUT_ARTIFACT_MAX_BYTES,
) -> None:
    """把已由容器白名单导出的 bytes 发布为宿主拥有的独立 inode。"""
    safe_target = _validate_leaf_name(target_name)
    data = bytes(content)
    if len(data) > int(max_bytes):
        raise OSError("白名单产物大小超过宿主发布上限")
    target_fd = _open_plain_directory(target_dir)
    temporary_name = f".export-{uuid.uuid4().hex}.tmp"
    temporary_created = False
    try:
        fd = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o600,
            dir_fd=target_fd,
        )
        temporary_created = True
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fchmod(fd, int(target_mode))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(
            temporary_name,
            safe_target,
            src_dir_fd=target_fd,
            dst_dir_fd=target_fd,
        )
        os.fsync(target_fd)
        temporary_created = False
    finally:
        if temporary_created:
            try:
                os.unlink(temporary_name, dir_fd=target_fd)
            except OSError:
                pass
        os.close(target_fd)


def _exported_output_text(result) -> str:
    content = getattr(result, "artifacts", {}).get("output.txt")
    if content is None:
        return result.stdout or ""
    return bytes(content).decode("utf-8", errors="replace")


def _result_exceeded_output_limit(result) -> bool:
    output_status = getattr(result, "artifact_statuses", {}).get(
        "output.txt"
    )
    return bool(
        getattr(result, "stdout_truncated", False)
        or output_status == "rejected"
    )


def _publish_exported_image(
    result,
    target_dir: str,
    requested_filename: str,
    stored_stem: str,
):
    requested_name = sanitize_output_image_filename(requested_filename)
    extension = os.path.splitext(requested_name)[1].lower()
    if extension not in IMAGE_FILE_EXTENSIONS:
        return None
    content = getattr(result, "artifacts", {}).get(requested_name)
    if content is None:
        return None
    target_name = f"{stored_stem}{extension}"
    try:
        _publish_exported_artifact(
            target_dir,
            target_name,
            content,
            max_bytes=OUTPUT_ARTIFACT_MAX_BYTES,
        )
    except Exception:
        return None
    return target_name


def _publish_exported_executable(result, run_dir: str) -> None:
    content = getattr(result, "artifacts", {}).get("a.out")
    if content is None:
        raise OSError("编译器未导出 a.out")
    _publish_exported_artifact(
        run_dir,
        "a.out",
        content,
        target_mode=0o555,
        max_bytes=OUTPUT_ARTIFACT_MAX_BYTES,
    )


def capture_output_image_file(sid: str, requested_filename: str, stored_stem: str):
    requested_name = sanitize_output_image_filename(requested_filename)
    source_path = os.path.join(sid, requested_name)
    if not _wait_for_output_file(source_path):
        return None

    _, ext = os.path.splitext(requested_name)
    ext = str(ext or "").lower()
    if not ext:
        ext = ".png"
    if ext not in IMAGE_FILE_EXTENSIONS:
        return None

    target_filename = f"{stored_stem}{ext}"
    try:
        _copy_regular_artifact_atomic(
            sid,
            sid,
            requested_name,
            target_filename,
        )
        return target_filename
    except Exception:
        return None


def capture_output_image_file_to_dir(source_dir: str, target_dir: str, requested_filename: str, stored_stem: str):
    requested_name = sanitize_output_image_filename(requested_filename)
    source_path = os.path.join(source_dir, requested_name)
    if not _wait_for_output_file(source_path):
        return None

    _, ext = os.path.splitext(requested_name)
    ext = str(ext or "").lower()
    if not ext:
        ext = ".png"
    if ext not in IMAGE_FILE_EXTENSIONS:
        return None

    target_filename = f"{stored_stem}{ext}"
    try:
        _copy_regular_artifact_atomic(
            source_dir,
            target_dir,
            requested_name,
            target_filename,
        )
        return target_filename
    except Exception:
        return None


def check_forbidden(code_content: str, forbidden_str: str):
    """禁用函数检查：逗号分割禁用函数名，按 func(...) 正则匹配。"""
    if not forbidden_str:
        return None
    match0 = re.search(
        r'here_is_user_code_fuck_fuck_fuck_hahaha(.*?)user_code_end_fuck_hahaha_fuck',
        code_content, re.DOTALL
    )
    code_content_check = match0.group(1) if match0 else code_content

    forbidden_funcs = [func.strip() for func in forbidden_str.split(",") if func.strip()]
    for func in forbidden_funcs:
        pattern = r'[^a-zA-Z0-9_](' + re.escape(func) + r')\s*\('
        if re.search(pattern, code_content_check):
            return f"Function '{func}' is not allowed"

        if func == "\\" and re.search(r'\\', code_content_check):
            return "Operator \\ is not allowed"
    return None


def read_output_with_fallback(output_filename: str, captured_stdout: str):
    output_path = os.path.abspath(output_filename)
    parent = os.path.dirname(output_path)
    name = _validate_leaf_name(os.path.basename(output_path))
    parent_fd = None
    try:
        parent_fd = _open_plain_directory(parent)
        fd = os.open(
            name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise OSError("output is not a regular file")
            chunks = []
            remaining = OUTPUT_TEXT_MAX_BYTES
            while remaining > 0:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            outp = b"".join(chunks).decode("utf-8", errors="replace")
            if int(info.st_size) > OUTPUT_TEXT_MAX_BYTES:
                outp += "\n...[输出文件超过 1 MiB，已截断]"
        finally:
            os.close(fd)
        try:
            os.unlink(name, dir_fd=parent_fd)
        except OSError:
            pass
        return outp
    except FileNotFoundError:
        return captured_stdout
    except Exception:
        return captured_stdout
    finally:
        if parent_fd is not None:
            os.close(parent_fd)


def safe_user_header_filename(filename):
    """兼容旧调用名：校验仓库文件的 POSIX 相对路径，不再扁平化。"""
    try:
        return normalize_repository_relative_path(filename)
    except InvalidRepositoryPath:
        return None


def _write_user_files(run_dir, user_files):
    """把提交绑定的仓库快照安全写入 ``run_dir/repository``。"""
    materialize_repository_tree(run_dir, user_files or {})


def cleanup_run_artifacts(sid, keep_images=True, keep_sources=False):
    """清理一次 attempt；只允许保留真实普通图片，永不保留容器源码 inode。"""
    del keep_sources  # 兼容旧调用签名；安全契约禁止保留源码。
    safe_sid = sanitize_sid(sid)
    try:
        root_fd = _open_run_root()
    except Exception:
        return
    try:
        try:
            root_entry = os.stat(
                safe_sid,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        if stat.S_ISLNK(root_entry.st_mode) or not stat.S_ISDIR(root_entry.st_mode):
            try:
                os.unlink(safe_sid, dir_fd=root_fd)
            except OSError:
                pass
            return

        try:
            run_fd = os.open(
                safe_sid,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=root_fd,
            )
        except OSError:
            return
        try:
            names = [entry.name for entry in os.scandir(run_fd)]
            for name in names:
                try:
                    info = os.stat(
                        name,
                        dir_fd=run_fd,
                        follow_symlinks=False,
                    )
                except OSError:
                    continue
                ext = os.path.splitext(name)[1].lower()
                if (
                    keep_images
                    and ext in IMAGE_FILE_EXTENSIONS
                    and stat.S_ISREG(info.st_mode)
                    and int(info.st_uid) == int(os.geteuid())
                    and int(info.st_nlink) == 1
                    and not (stat.S_IMODE(info.st_mode) & 0o022)
                    and int(info.st_size) <= OUTPUT_ARTIFACT_MAX_BYTES
                ):
                    continue
                try:
                    _remove_entry_at(run_fd, name)
                except Exception:
                    pass
        finally:
            os.close(run_fd)
        try:
            os.rmdir(safe_sid, dir_fd=root_fd)
        except OSError:
            pass
    finally:
        os.close(root_fd)


def cleanup_run_artifacts_for_submission(submission_id, keep_images=True):
    """清理某次提交可能用到的所有运行目录的临时产物。"""
    sid = str(submission_id)
    prefix = f"eoj-{sid}-"
    quick_compile_name = f"eoj-quick-compile-{sid}"
    exact = {f"eoj-batch-{sid}", f"eoj-quick-compile-{sid}"}
    if not os.path.isdir(JUDGER_RUN_ROOT):
        return
    try:
        for name in os.listdir(JUDGER_RUN_ROOT):
            if name in exact or name.startswith(prefix):
                cleanup_run_artifacts(
                    name,
                    keep_images=keep_images,
                    keep_sources=False,
                )
    except Exception:
        pass


def reap_stale_run_dirs(ttl_seconds):
    """删除 JUDGER_RUN_ROOT 下早于 ttl 的整个运行子目录。"""
    if not ttl_seconds or ttl_seconds <= 0:
        return 0
    now = time.time()
    removed = 0
    try:
        root_fd = _open_run_root()
    except Exception:
        return 0
    try:
        for entry in os.scandir(root_fd):
            name = entry.name
            if name == "submission_archive" or name.startswith("."):
                continue
            try:
                info = os.stat(
                    name,
                    dir_fd=root_fd,
                    follow_symlinks=False,
                )
            except OSError:
                continue
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                continue
            if now - float(info.st_mtime) <= ttl_seconds:
                continue
            try:
                _remove_entry_at(root_fd, name)
            except Exception:
                continue
            removed += 1
    finally:
        os.close(root_fd)
    return removed



def _timeout_sec_from_ns(time_limit_ns, factor=1.2):
    """将纳秒时间限制转换为秒（带 factor 余量），最小 1 秒。"""
    return max(1.0, (time_limit_ns or 0) * factor / 1e9)


def _guard_timeout(base_sec):
    """Docker 操作的 Python 侧总超时 = 基础时间 + 固定缓冲。"""
    return max(1.0, float(base_sec or 0)) + 10.0


def _measured_exec_time_ns(result, tle_ns):
    """返回容器内部测得的运行时间。

    正常路径下由 docker_sandbox 的 shell wrapper 写回 elapsed_ns；如果外层
    Docker guard 超时导致 wrapper 来不及输出 marker，则把本次运行视作超时。
    """
    elapsed_ns = getattr(result, "elapsed_ns", None)
    if isinstance(elapsed_ns, int) and elapsed_ns >= 0:
        return elapsed_ns
    if getattr(result, "returncode", None) == 124 and tle_ns:
        return int(tle_ns) + 1
    return 0


def _result_was_oom_killed(result):
    return bool(
        getattr(result, "oom_killed", False)
        or getattr(result, "returncode", None) == 137
    )


# ========== 单次运行（Octave / Python / C / C++）==========
def run_octave(data):
    """Octave/MATLAB 单次运行。"""
    artifact_dir = _prepare_run_dir(data.get("sid", ""))
    run_dir = _prepare_execution_workspace(artifact_dir)
    user_input = data.get("input", "")
    code_content = data.get("code", "")
    tle = data.get("timeLimit")  # ns
    forbidden_funcs = data.get("forbidden", "")
    output_image_filename = data.get("outputImageFilename", "output.png")

    forbid_msg = check_forbidden(code_content, forbidden_funcs)
    if forbid_msg:
        return {
            "status": "Forbidden",
            "exitStatus": 11,
            "files": {"stdout": forbid_msg, "stderr": forbid_msg},
            "time": 0,
            "memory": 0,
        }

    _write_text_file_exclusive(run_dir, "a.m", code_content)
    _write_source_debug_artifacts(run_dir, data, "octave")

    timeLim_sec = _timeout_sec_from_ns(tle, factor=1.1)
    container_cmd = _timeout_cmd(
        timeLim_sec,
        "octave",
        "/sandbox/a.m",
    )
    safe_image_name = sanitize_output_image_filename(
        output_image_filename
    )

    result = run_case_in_container(
        container_cmd,
        run_dir=run_dir,
        input_text=user_input,
        timeout_sec=_guard_timeout(timeLim_sec),
        output_name="output.txt",
        output_max_bytes=OUTPUT_TEXT_MAX_BYTES,
        image_name=safe_image_name,
        image_max_bytes=OUTPUT_ARTIFACT_MAX_BYTES,
    )
    exec_time = _measured_exec_time_ns(result, tle)

    outp = _exported_output_text(result)

    status = "Accepted"
    exval = 0
    stderr = result.stderr or ""
    if len(stderr) > 300:
        stderr = stderr[:300] + "..."

    if exec_time > (tle or 0):
        status = "Time Limit Exceeded"
        exval = 9
    elif _result_was_oom_killed(result):
        status = "Memory Limit Exceeded"
        exval = 10
    elif result.returncode != 0:
        status = "Nonzero Exit Status"
        exval = result.returncode
    elif _result_exceeded_output_limit(result):
        status = "Output Limit Exceeded"
        exval = 12

    files_dict = {"stdout": outp, "stderr": stderr}
    stored_image_filename = _publish_exported_image(
        result,
        artifact_dir,
        safe_image_name,
        "output",
    )
    if stored_image_filename:
        files_dict[stored_image_filename] = True

    return {
        "status": status,
        "exitStatus": exval,
        "files": files_dict,
        "time": exec_time,
        "memory": 0,
    }


def run_py(data):
    """Python 单次运行。"""
    artifact_dir = _prepare_run_dir(data.get("sid", ""))
    run_dir = _prepare_execution_workspace(artifact_dir)
    user_input = data.get("input", "")
    code_content = data.get("code", "")
    tle = data.get("timeLimit")  # ns
    forbidden_funcs = data.get("forbidden", "")
    output_image_filename = data.get("outputImageFilename", "output.png")

    forbid_msg = check_forbidden(code_content, forbidden_funcs)
    if forbid_msg:
        return {
            "status": "Forbidden",
            "exitStatus": 11,
            "files": {"stdout": forbid_msg, "stderr": forbid_msg},
            "time": 0,
            "memory": 0,
        }

    _write_text_file_exclusive(run_dir, "main.py", code_content)
    _write_source_debug_artifacts(run_dir, data, "python")

    timeLim_sec = _timeout_sec_from_ns(tle, factor=1.2)
    container_cmd = _timeout_cmd(
        timeLim_sec,
        "python3",
        "-I",
        "-u",
        "/sandbox/main.py",
    )
    safe_image_name = sanitize_output_image_filename(
        output_image_filename
    )

    result = run_case_in_container(
        container_cmd,
        run_dir=run_dir,
        input_text=user_input,
        timeout_sec=_guard_timeout(timeLim_sec),
        output_name="output.txt",
        output_max_bytes=OUTPUT_TEXT_MAX_BYTES,
        image_name=safe_image_name,
        image_max_bytes=OUTPUT_ARTIFACT_MAX_BYTES,
    )
    exec_time = _measured_exec_time_ns(result, tle)

    outp = _exported_output_text(result)

    status = "Accepted"
    exval = 0
    stderr = result.stderr or ""
    if len(stderr) > 300:
        stderr = stderr[:300] + "..."

    if exec_time > (tle or 0):
        status = "Time Limit Exceeded"
        exval = 9
    elif _result_was_oom_killed(result):
        status = "Memory Limit Exceeded"
        exval = 10
    elif result.returncode != 0:
        status = "Runtime Error"
        exval = result.returncode
    elif _result_exceeded_output_limit(result):
        status = "Output Limit Exceeded"
        exval = 12

    files_dict = {"stdout": outp, "stderr": stderr}
    stored_image_filename = _publish_exported_image(
        result,
        artifact_dir,
        safe_image_name,
        "output",
    )
    if stored_image_filename:
        files_dict[stored_image_filename] = True

    return {
        "status": status,
        "exitStatus": exval,
        "files": files_dict,
        "time": exec_time,
        "memory": 0,
    }


def _run_compiled_single(data, language):
    """C/C++ 单次运行。"""
    artifact_dir = _prepare_run_dir(data.get("sid", ""))
    run_dir = _prepare_execution_workspace(artifact_dir)
    user_input = data.get("input", "")
    code_content = data.get("code", "")
    tle = data.get("timeLimit")  # ns
    forbidden_funcs = data.get("forbidden", "")
    output_image_filename = data.get("outputImageFilename", "output.png")
    user_files = data.get("user_files", {})

    forbid_msg = check_forbidden(code_content, forbidden_funcs)
    if forbid_msg:
        return {
            "status": "Forbidden",
            "exitStatus": 11,
            "files": {"stdout": forbid_msg, "stderr": forbid_msg},
            "time": 0,
            "memory": 0,
        }

    if language == "cpp":
        src_name = "main.cpp"
        compile_err_cap = 3000
    else:
        src_name = "main.c"
        compile_err_cap = 300
    compile_cmd = build_compile_cmd(
        language,
        source_path=f"/sandbox/{src_name}",
    )

    _write_text_file_exclusive(run_dir, src_name, code_content)

    _write_user_files(run_dir, user_files)
    _write_source_debug_artifacts(run_dir, data, language)

    # Compile
    compile_res = run_case_in_container(
        compile_cmd,
        run_dir=run_dir,
        timeout_sec=45,
        executable_name="a.out",
        executable_max_bytes=OUTPUT_ARTIFACT_MAX_BYTES,
    )
    if compile_res.returncode != 0:
        stderr = compile_res.stderr or ""
        if len(stderr) > compile_err_cap:
            stderr = stderr[:compile_err_cap] + "..."
        return {
            "status": "Compile Error",
            "exitStatus": compile_res.returncode,
            "files": {"stdout": compile_res.stdout or "", "stderr": stderr},
            "time": 0,
            "memory": 0,
        }
    try:
        _publish_exported_executable(compile_res, run_dir)
    except Exception as exc:
        return {
            "status": "Compile Error",
            "exitStatus": -1,
            "files": {
                "stdout": compile_res.stdout or "",
                "stderr": f"编译产物导出失败：{exc}",
            },
            "time": 0,
            "memory": 0,
        }

    # Run
    timeLim_sec = _timeout_sec_from_ns(tle, factor=1.2)
    run_cmd = _timeout_cmd(timeLim_sec, "/sandbox/a.out")
    safe_image_name = sanitize_output_image_filename(
        output_image_filename
    )

    run_res = run_case_in_container(
        run_cmd,
        run_dir=run_dir,
        input_text=user_input,
        timeout_sec=_guard_timeout(timeLim_sec),
        output_name="output.txt",
        output_max_bytes=OUTPUT_TEXT_MAX_BYTES,
        image_name=safe_image_name,
        image_max_bytes=OUTPUT_ARTIFACT_MAX_BYTES,
    )
    exec_time = _measured_exec_time_ns(run_res, tle)

    outp = _exported_output_text(run_res)

    status = "Accepted"
    exval = 0
    stderr = run_res.stderr or ""
    if len(stderr) > 300:
        stderr = stderr[:300] + "..."

    if exec_time > (tle or 0):
        status = "Time Limit Exceeded"
        exval = 9
    elif _result_was_oom_killed(run_res):
        status = "Memory Limit Exceeded"
        exval = 10
    elif run_res.returncode != 0:
        status = "Runtime Error"
        exval = run_res.returncode
    elif _result_exceeded_output_limit(run_res):
        status = "Output Limit Exceeded"
        exval = 12

    files_dict = {"stdout": outp, "stderr": stderr}
    stored_image_filename = _publish_exported_image(
        run_res,
        artifact_dir,
        safe_image_name,
        "output",
    )
    if stored_image_filename:
        files_dict[stored_image_filename] = True

    return {
        "status": status,
        "exitStatus": exval,
        "files": files_dict,
        "time": exec_time,
        "memory": 0,
    }


def run_c(data):
    return _run_compiled_single(data, "c")


def run_cpp(data):
    return _run_compiled_single(data, "cpp")


# ========== 批量评测：编译一次，运行多个测试点 ==========
def _batch_evaluate_stream(data, language):
    """编译一次、逐测试点启动独立短生命周期容器的生成器。"""
    code_content = data.get("code", "")
    test_cases = data.get("test_cases", [])
    tle = data.get("timeLimit")  # ns
    forbidden_funcs = data.get("forbidden", "")
    user_files = data.get("user_files", {})
    output_image_filename = data.get("outputImageFilename", "output.png")

    try:
        artifact_dir = _prepare_run_dir(data.get("sid", ""))
        run_dir = _prepare_execution_workspace(artifact_dir)
        forbid_msg = check_forbidden(code_content, forbidden_funcs)
        if forbid_msg:
            yield {"event": "compile", "status": "forbidden", "stderr": forbid_msg}
            yield {"event": "done", "ok": False}
            return

        if language == "cpp":
            src_name = "main.cpp"
            compile_err_cap = 3000
        else:
            src_name = "main.c"
            compile_err_cap = 300
        compile_cmd = build_compile_cmd(
            language,
            source_path=f"/sandbox/{src_name}",
        )

        _write_text_file_exclusive(run_dir, src_name, code_content)

        _write_user_files(run_dir, user_files)
        _write_source_debug_artifacts(run_dir, data, language)

        # 编译只执行一次；linker 产物随后换成宿主拥有的只读 inode，后续任一
        # 测试点都不能篡改下一测试点将执行的程序。
        compile_res = run_case_in_container(
            compile_cmd,
            run_dir=run_dir,
            timeout_sec=45,
            executable_name="a.out",
            executable_max_bytes=OUTPUT_ARTIFACT_MAX_BYTES,
        )
        if compile_res.returncode != 0:
            stderr = compile_res.stderr or ""
            if len(stderr) > compile_err_cap:
                stderr = stderr[:compile_err_cap] + "..."
            yield {"event": "compile", "status": "error", "stderr": stderr}
            yield {"event": "done", "ok": False}
            return
        try:
            _publish_exported_executable(compile_res, run_dir)
        except Exception as exc:
            yield {
                "event": "compile",
                "status": "error",
                "stderr": f"编译产物导出失败：{exc}",
            }
            yield {"event": "done", "ok": False}
            return

        yield {"event": "compile", "status": "success", "stderr": ""}

        # 每个测试点使用独立短生命周期容器。docker run 的启动耗时不在容器内
        # elapsed marker 中；PID 1 退出后 Docker 会销毁该 case 的全部后台进程。
        for i, test_case in enumerate(test_cases):
            user_input = test_case.get("input", "")
            timeLim_sec = _timeout_sec_from_ns(tle, factor=1.2)
            run_cmd = _timeout_cmd(timeLim_sec, "/sandbox/a.out")
            safe_image_name = sanitize_output_image_filename(
                output_image_filename
            )

            run_res = run_case_in_container(
                run_cmd,
                run_dir=run_dir,
                input_text=user_input,
                timeout_sec=_guard_timeout(timeLim_sec),
                output_name="output.txt",
                output_max_bytes=OUTPUT_TEXT_MAX_BYTES,
                image_name=safe_image_name,
                image_max_bytes=OUTPUT_ARTIFACT_MAX_BYTES,
            )
            exec_time = _measured_exec_time_ns(run_res, tle)

            outp = _exported_output_text(run_res)

            status = "Accepted"
            exval = 0
            stderr = run_res.stderr or ""
            if len(stderr) > 300:
                stderr = stderr[:300] + "..."

            if exec_time > (tle or 0):
                status = "Time Limit Exceeded"
                exval = 9
            elif _result_was_oom_killed(run_res):
                status = "Memory Limit Exceeded"
                exval = 10
            elif run_res.returncode != 0:
                status = "Runtime Error"
                exval = run_res.returncode
            elif _result_exceeded_output_limit(run_res):
                status = "Output Limit Exceeded"
                exval = 12

            files_dict = {"stdout": outp, "stderr": stderr}
            stored_image_filename = _publish_exported_image(
                run_res,
                artifact_dir,
                safe_image_name,
                f"output_{i}",
            )
            if stored_image_filename:
                files_dict[stored_image_filename] = True

            yield {"event": "test_result", "result": {
                "test_case_index": i,
                "status": status,
                "exitStatus": exval,
                "files": files_dict,
                "time": exec_time,
                "memory": 0,
            }}

        yield {"event": "done", "ok": True}
    except Exception as e:
        yield {"event": "error", "message": f"Failed to stream batch evaluate {language}: {str(e)}"}
        yield {"event": "done", "ok": False}


# ========== 批量评测：解释型语言（Octave / Python），每点独立容器 ==========
def _batch_evaluate_script_stream(data, language):
    """解释型语言（Octave/Python）批量评测生成器。

    每个测试点各自使用短生命周期容器，防止前一测试点留下 setsid/background
    进程观察或篡改后一测试点。计时仍由容器内 wrapper 生成，不含 docker run
    启动耗时。
    """
    code_content = data.get("code", "")
    test_cases = data.get("test_cases", [])
    tle = data.get("timeLimit")  # ns
    forbidden_funcs = data.get("forbidden", "")
    output_image_filename = data.get("outputImageFilename", "output.png")

    try:
        artifact_dir = _prepare_run_dir(data.get("sid", ""))
        run_dir = _prepare_execution_workspace(artifact_dir)
        forbid_msg = check_forbidden(code_content, forbidden_funcs)
        if forbid_msg:
            yield {"event": "compile", "status": "forbidden", "stderr": forbid_msg}
            yield {"event": "done", "ok": False}
            return

        if language in ("matlab", "octave", "hello"):
            src_name = "a.m"
            factor = 1.1
            run_status_nonzero = "Nonzero Exit Status"
            make_cmd = lambda t: _timeout_cmd(
                t,
                "octave",
                "/sandbox/a.m",
            )
        else:  # python
            src_name = "main.py"
            factor = 1.2
            run_status_nonzero = "Runtime Error"
            make_cmd = lambda t: _timeout_cmd(
                t,
                "python3",
                "-I",
                "-u",
                "/sandbox/main.py",
            )

        _write_text_file_exclusive(run_dir, src_name, code_content)
        _write_source_debug_artifacts(run_dir, data, language)

        # 解释型语言无编译步骤，直接报告编译成功以复用上层 stream 处理逻辑。
        yield {"event": "compile", "status": "success", "stderr": ""}

        if language in ("matlab", "octave", "hello"):
            _warmup_octave_plot_in_container(run_dir)

        for i, test_case in enumerate(test_cases):
            user_input = test_case.get("input", "")

            timeLim_sec = _timeout_sec_from_ns(tle, factor=factor)
            run_cmd = make_cmd(timeLim_sec)
            safe_image_name = sanitize_output_image_filename(
                output_image_filename
            )

            run_res = run_case_in_container(
                run_cmd,
                run_dir=run_dir,
                input_text=user_input,
                timeout_sec=_guard_timeout(timeLim_sec),
                output_name="output.txt",
                output_max_bytes=OUTPUT_TEXT_MAX_BYTES,
                image_name=safe_image_name,
                image_max_bytes=OUTPUT_ARTIFACT_MAX_BYTES,
            )
            exec_time = _measured_exec_time_ns(run_res, tle)

            outp = _exported_output_text(run_res)

            status = "Accepted"
            exval = 0
            stderr = run_res.stderr or ""
            if len(stderr) > 300:
                stderr = stderr[:300] + "..."

            if exec_time > (tle or 0):
                status = "Time Limit Exceeded"
                exval = 9
            elif _result_was_oom_killed(run_res):
                status = "Memory Limit Exceeded"
                exval = 10
            elif run_res.returncode != 0:
                status = run_status_nonzero
                exval = run_res.returncode
            elif _result_exceeded_output_limit(run_res):
                status = "Output Limit Exceeded"
                exval = 12

            files_dict = {"stdout": outp, "stderr": stderr}
            stored_image_filename = _publish_exported_image(
                run_res,
                artifact_dir,
                safe_image_name,
                f"output_{i}",
            )
            if stored_image_filename:
                files_dict[stored_image_filename] = True

            yield {"event": "test_result", "result": {
                "test_case_index": i,
                "status": status,
                "exitStatus": exval,
                "files": files_dict,
                "time": exec_time,
                "memory": 0,
            }}

        yield {"event": "done", "ok": True}
    except Exception as e:
        yield {"event": "error", "message": f"Failed to stream script batch evaluate {language}: {str(e)}"}
        yield {"event": "done", "ok": False}


# ========== 对外分派 ==========
def run_single(language, data):
    """单次运行分派。language: matlab/octave、c、cpp、py/python。"""
    lang = str(language or "").strip().lower()
    if lang in ("matlab", "octave", "hello"):
        return run_octave(data)
    if lang == "c":
        return run_c(data)
    if lang in ("cpp", "c++"):
        return run_cpp(data)
    if lang in ("py", "python", "python3"):
        return run_py(data)
    raise ValueError(f"run_single: 不支持的语言 {language!r}")


def batch_evaluate_stream(language, data):
    """流式批量评测分派（生成器）。

    c/cpp：编译一次，再为每个测试点启动独立容器。
    matlab/octave、python：每个测试点启动独立容器。
    """
    lang = str(language or "").strip().lower()
    if lang in ("cpp", "c++"):
        return _batch_evaluate_stream(data, "cpp")
    if lang == "c":
        return _batch_evaluate_stream(data, "c")
    if lang in ("matlab", "octave", "hello"):
        return _batch_evaluate_script_stream(data, "octave")
    if lang in ("py", "python", "python3"):
        return _batch_evaluate_script_stream(data, "python")
    raise ValueError(f"batch_evaluate_stream: 不支持的语言 {language!r}")


def batch_evaluate(language, data):
    """非流式批量评测。返回 {compile_result, test_results}。"""
    test_results = []
    for event in batch_evaluate_stream(language, data):
        ev = event.get("event")
        if ev == "compile":
            if event.get("status") != "success":
                return {
                    "compile_result": {"status": event.get("status"), "stderr": event.get("stderr", "")},
                    "test_results": [],
                }
        elif ev == "test_result":
            test_results.append(event.get("result"))
        elif ev == "error":
            raise RuntimeError(event.get("message") or "batch evaluate failed")
    return {"compile_result": {"status": "success", "stderr": ""}, "test_results": test_results}
