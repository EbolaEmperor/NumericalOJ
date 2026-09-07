"""把服务器拉取的 Git 提交转为现有作品快照入口可消费的流。"""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

from backend.oj_modules.vibehub import quotas, storage

GIT_TIMEOUT_SECONDS = 180
MAX_GIT_BYTES = storage.MAX_ARCHIVE_BYTES
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/\-]{0,199}$")
_SCP_RE = re.compile(r"^(?:[A-Za-z0-9_.-]+@)?[A-Za-z0-9][A-Za-z0-9.-]*:[A-Za-z0-9_./-]+$")


class GitSourceError(ValueError):
    pass


def validate_source(url, ref=None) -> tuple[str, str]:
    if not isinstance(url, str) or not url or len(url) > 2048 or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url):
        raise GitSourceError("请填写有效的 Git 仓库地址")
    if "://" in url:
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError as exc:
            raise GitSourceError("Git 仓库地址或端口无效") from exc
        if (parsed.scheme not in {"https", "http", "ssh"} or not parsed.hostname or
                not parsed.path.strip("/") or parsed.query or parsed.fragment or
                parsed.password is not None or (parsed.username and parsed.scheme != "ssh") or
                (port is not None and not 1 <= port <= 65535)):
            raise GitSourceError("Git 地址仅支持无内嵌密码的 HTTPS、HTTP 或 SSH 仓库")
    elif not _SCP_RE.fullmatch(url):
        raise GitSourceError("Git 地址须为 HTTPS、HTTP、SSH 或 user@host:owner/repo.git 格式")
    value = ref or ""
    if not isinstance(value, str) or (value and (not _REF_RE.fullmatch(value) or ".." in value or value.endswith(("/", ".", ".lock")) or "//" in value or "/." in value)):
        raise GitSourceError("Git 分支或标签格式无效")
    return url, value


def _git_environment() -> dict[str, str]:
    # 保留服务器的 SSH 身份；清除可改变仓库目录、配置或传输方式的 Git 环境。
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_SSH_COMMAND="ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10")
    return env


def _run(arguments, *, root: Path, output: Path, limit: int = MAX_GIT_BYTES, timeout_seconds: float | None = None) -> None:
    command = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.allow=never",
               "-c", "protocol.https.allow=always", "-c", "protocol.http.allow=always",
               "-c", "protocol.ssh.allow=always", "-c", "http.followRedirects=false",
               "-c", "credential.helper=", *arguments]
    deadline = time.monotonic() + (GIT_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds)
    with output.open("wb") as stdout, tempfile.TemporaryFile(dir=root) as stderr:
        try:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr, env=_git_environment(),
                                       start_new_session=True, stdin=subprocess.DEVNULL)
        except OSError as exc:
            raise GitSourceError("服务器无法运行 Git，请联系管理员") from exc
        try:
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise GitSourceError("Git 拉取或归档超时，请检查仓库是否可访问")
                if quotas.logical_tree_bytes(root) > limit or os.fstat(stderr.fileno()).st_size > 1024**2:
                    raise GitSourceError("Git 仓库或引用列表超过暂存上限")
                time.sleep(.1)
            if process.returncode:
                # 不把远端输出或服务器 SSH 细节直接返回到浏览器。
                raise GitSourceError("Git 操作失败，请检查地址、分支和服务器的仓库访问权限")
            if quotas.logical_tree_bytes(root) > limit:
                raise GitSourceError("Git 仓库或引用列表超过暂存上限")
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()


@contextmanager
def git_package(url, ref=None, *, upload_root=None):
    """浅克隆、不 checkout、不运行仓库文件；固定 commit 后流式生成 ZIP。"""
    url, ref = validate_source(url, ref)
    root = upload_root or storage.VIBEHUB_UPLOAD_ROOT
    with quotas.storage_mutation_lock(root):
        staging = quotas.create_upload_staging_directory(root)
    try:
        repo = staging / "repository.git"
        output = staging / "git-output"
        explicit_ref = ref.startswith(("refs/heads/", "refs/tags/"))
        branch = ["--branch", ref] if ref and not explicit_ref else []
        _run(["clone", "--bare", "--depth", "1", "--single-branch", "--no-tags", *branch, "--", url, str(repo)],
             root=staging, output=output)
        if explicit_ref:
            _run(["--git-dir", str(repo), "fetch", "--depth", "1", "--no-tags", "--", url, ref], root=staging, output=output)
        _run(["--git-dir", str(repo), "rev-parse", "FETCH_HEAD^{commit}" if explicit_ref else "HEAD^{commit}"], root=staging, output=output)
        commit = output.read_text().strip()
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
            raise GitSourceError("Git 没有返回有效的提交标识")
        _run(["--git-dir", str(repo), "ls-tree", "-r", "-z", commit], root=staging, output=output)
        with output.open("rb") as entries:
            # ls-tree 输出受到总暂存上限保护；逐条读取，避免随仓库体积占满内存。
            pending = b""
            while chunk := entries.read(65536):
                pending += chunk
                parts = pending.split(b"\0")
                pending = parts.pop()
                if len(pending) > 16384 or any(item.startswith(b"160000 ") for item in parts):
                    raise GitSourceError("作品仓库不支持子模块或过长路径，请提交完整源码")
        output.unlink()
        archive = staging / "package.zip"
        # Git 对象与归档各自受 5 GiB 上限约束；归档阶段容许两份暂存同时存在。
        _run(["--git-dir", str(repo), "archive", "--format=zip", "-0", commit],
             root=staging, output=archive, limit=2 * MAX_GIT_BYTES)
        if archive.stat().st_size > storage.MAX_ARCHIVE_BYTES:
            raise GitSourceError("Git 源码归档超过 5 GiB 上限")
        shutil.rmtree(repo)
        with archive.open("rb") as stream:
            yield stream, {"kind": "git", "url": url, "ref": ref, "commit": commit}
    except quotas.VibeHubQuotaPolicyError as exc:
        raise GitSourceError("Git 暂存目录超出存储策略限制") from exc
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def list_remote_refs(url, *, upload_root=None):
    """只读取远端引用；与实际提交使用相同的传输和身份限制。"""
    url, _ = validate_source(url)
    root = upload_root or storage.VIBEHUB_UPLOAD_ROOT
    with quotas.storage_mutation_lock(root):
        staging = quotas.create_upload_staging_directory(root)
    try:
        output = staging / "refs"
        _run(["ls-remote", "--symref", "--", url, "HEAD", "refs/heads/*", "refs/tags/*"],
             root=staging, output=output, limit=1024**2, timeout_seconds=20)
        branches, tags, default_ref, head = {}, set(), "", ""
        for line in output.read_text(encoding="utf-8").splitlines():
            value, sep, name = line.partition("\t")
            if not sep:
                continue
            if name == "HEAD" and value.startswith("ref: refs/heads/"):
                default_ref = value.removeprefix("ref: refs/heads/")
            elif re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value):
                if name == "HEAD":
                    head = value
                elif name.startswith("refs/heads/"):
                    branches[name.removeprefix("refs/heads/")] = value
                elif name.startswith("refs/tags/") and not name.endswith("^{}"):
                    tags.add(name.removeprefix("refs/tags/"))
        if default_ref not in branches:
            matches = [name for name, commit in branches.items() if commit == head]
            default_ref = matches[0] if len(matches) == 1 else ""
        refs = ([{"value": name, "name": name, "kind": "branch"} for name in sorted(branches, key=lambda name: (name != default_ref, name))]
                + [{"value": "refs/tags/" + name, "name": name, "kind": "tag"} for name in sorted(tags)])
        if not refs:
            raise GitSourceError("仓库中没有可提交的分支或标签")
        return {"default_ref": default_ref, "refs": refs}
    except (UnicodeError, quotas.VibeHubQuotaPolicyError) as exc:
        raise GitSourceError("无法读取仓库分支列表") from exc
    finally:
        shutil.rmtree(staging, ignore_errors=True)
