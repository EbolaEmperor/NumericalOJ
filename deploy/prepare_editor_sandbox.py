#!/usr/bin/env python3
"""为受 AppArmor userns 限制的宿主准备官方收窄 Bubblewrap 策略。"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.backup import apt  # noqa: E402

PROFILE_SOURCE = Path(__file__).with_name("apparmor") / "numericaloj-editor-bwrap"
PROFILE_DESTINATION = Path("/etc/apparmor.d/numericaloj-editor-bwrap")
PARSER = "/usr/sbin/apparmor_parser"
MARKER = "# Managed by NumericalOJ: editor Bubblewrap user namespace policy.\n"
RESTRICTION = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")


def _probe():
    binary = shutil.which("bwrap")
    if binary is None:
        raise apt.ProvisioningError("编辑器沙箱缺少 Bubblewrap")
    # 与真实语言服务使用相同的文件系统和禁网包装，只执行宿主 /usr/bin/true。
    from backend.oj_modules.editor.language_server import sandbox_language_server_command

    with tempfile.TemporaryDirectory(prefix="numoj-editor-sandbox-probe-") as temporary:
        command = sandbox_language_server_command("/usr/bin/true", (), Path(temporary))
        return subprocess.run(command, capture_output=True, text=True, timeout=20,
                              check=False, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})


def _private_system_file(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) & 0o022 or info.st_size > 1024**2):
        raise apt.ProvisioningError(f"系统沙箱配置必须为 root 所有且不可由其他用户写入：{path}")
    return path.read_text(encoding="utf-8")


def install_profile(*, run=subprocess.run):
    """仅供 sudo 子进程使用；目标路径固定，不接收用户路径或策略内容。"""
    if os.geteuid() != 0:
        raise apt.ProvisioningError("安装 AppArmor 沙箱策略需要 sudo 权限")
    directory = PROFILE_DESTINATION.parent
    for path in (directory, Path("/usr/bin/bwrap"), Path(PARSER)):
        info = path.lstat()
        if info.st_uid != 0 or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o022:
            raise apt.ProvisioningError(f"系统沙箱路径不可信：{path}")
    old = None
    if PROFILE_DESTINATION.exists() or PROFILE_DESTINATION.is_symlink():
        old = _private_system_file(PROFILE_DESTINATION)
        if not old.startswith(MARKER):
            raise apt.ProvisioningError("已有外部 AppArmor 沙箱策略，拒绝覆盖")
    # 不替换管理员或发行版已存在的 bwrap attachment，包括被管理员禁用的策略。
    for path in directory.iterdir():
        if path == PROFILE_DESTINATION or not path.is_file():
            continue
        content = _private_system_file(path)
        if "/usr/bin/bwrap" in content:
            raise apt.ProvisioningError("已有外部 Bubblewrap AppArmor 策略，请由管理员核验加载状态")
    source_info = PROFILE_SOURCE.lstat()
    if not stat.S_ISREG(source_info.st_mode) or source_info.st_size > 64 * 1024:
        raise apt.ProvisioningError("项目 Bubblewrap 策略不是有效普通文件")
    content = PROFILE_SOURCE.read_text(encoding="utf-8")
    if not content.startswith(MARKER):
        raise apt.ProvisioningError("项目 Bubblewrap 策略缺少受管标记")
    # 先做不加载内核、不写 parser cache 的完整语法检查。
    compiled = run([PARSER, "--skip-kernel-load", "--skip-cache", str(PROFILE_SOURCE)],
                   check=False, capture_output=True, text=True, timeout=30)
    if compiled.returncode:
        raise apt.ProvisioningError("官方 Bubblewrap AppArmor 策略编译失败")
    if old != content:
        descriptor, name = tempfile.mkstemp(prefix=".numericaloj-editor-bwrap-", dir=directory)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), 0o644)
            temporary.replace(PROFILE_DESTINATION)
        finally:
            temporary.unlink(missing_ok=True)
    loaded = run([PARSER, "--replace", "--skip-cache", str(PROFILE_DESTINATION)],
                 check=False, capture_output=True, text=True, timeout=30)
    if loaded.returncode:
        if old is None:
            remove_created_profile(run=run)
        raise apt.ProvisioningError("官方 Bubblewrap AppArmor 策略加载失败；本轮新建策略已回收，既有策略保持原状"
                                    if old is None else "官方 Bubblewrap AppArmor 策略加载失败，已停止部署")
    return old is None


def remove_created_profile(*, run=subprocess.run):
    """只回收本轮刚创建且仍与当前受管内容一致的独有策略。"""
    if os.geteuid() != 0:
        raise apt.ProvisioningError("回收 AppArmor 沙箱策略需要 sudo 权限")
    content = _private_system_file(PROFILE_DESTINATION)
    if not content.startswith(MARKER) or content != PROFILE_SOURCE.read_text(encoding="utf-8"):
        raise apt.ProvisioningError("沙箱策略已改变，拒绝回收")
    result = run([PARSER, "--remove", "--skip-cache", str(PROFILE_DESTINATION)],
                 check=False, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise apt.ProvisioningError("本轮新建沙箱策略卸载失败，已保留现场")
    PROFILE_DESTINATION.unlink()
    print("已卸载本轮新建的 NumericalOJ 沙箱策略；既有策略未改动")


def ensure(*, run=apt.run_command):
    if platform.system() != "Linux":
        return False
    result = _probe()
    if result.returncode == 0:
        return False
    known_denial = "Operation not permitted" in result.stderr or "Permission denied" in result.stderr
    if (not RESTRICTION.is_file() or RESTRICTION.read_text().strip() != "1" or not known_denial
            or shutil.which("bwrap") != "/usr/bin/bwrap" or not Path(PARSER).is_file()):
        raise apt.ProvisioningError("Bubblewrap 完整隔离不可用，拒绝降低沙箱安全设置：" + result.stderr.strip()[-1000:])
    apt._checked(run, [apt.SUDO, "-v"], purpose="验证编辑器沙箱策略安装权限", interactive=True)
    prefix = [apt.SUDO, sys.executable, "-I", "-B", str(Path(__file__).resolve())]
    installed = apt._checked(run, [*prefix, "--install-profile"], purpose="准备官方 Bubblewrap AppArmor 策略")
    created = json.loads(installed.stdout)["created"]
    if type(created) is not bool:
        raise apt.ProvisioningError("沙箱策略安装返回无效状态")
    try:
        verified = _probe()
        if verified.returncode:
            raise apt.ProvisioningError("Bubblewrap AppArmor 策略加载后完整隔离仍不可用：" + verified.stderr.strip()[-1000:])
    except BaseException:
        if created:
            apt._checked(run, [*prefix, "--remove-created-profile"], purpose="回收本轮新建沙箱策略")
            print("编辑器沙箱核验失败，已卸载本轮新建的独有策略；既有策略未改动", file=sys.stderr)
        raise
    print("编辑器 Bubblewrap userns 策略已核验；全局 AppArmor 限制保持启用")
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-profile", action="store_true")
    parser.add_argument("--remove-created-profile", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.install_profile:
            print(json.dumps({"created": install_profile()}))
        elif args.remove_created_profile:
            remove_created_profile()
        else:
            ensure()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"[editor-sandbox] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
