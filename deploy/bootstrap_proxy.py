#!/usr/bin/env python3
"""将首次本机站点显式使用的下载代理保留给 Docker 与后续构建。"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from urllib.parse import urlsplit


class BootstrapProxyError(RuntimeError):
    pass


def _proxy_values(environ):
    values = {}
    for lower, upper in (("http_proxy", "HTTP_PROXY"), ("https_proxy", "HTTPS_PROXY")):
        value = environ.get(lower) or environ.get(upper)
        if not value:
            continue
        if not isinstance(value, str):
            raise BootstrapProxyError("下载代理配置必须是字符串")
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or any(ord(c) < 32 for c in value):
            raise BootstrapProxyError("首次下载代理必须是有效的 HTTP(S) URL")
        values[upper] = value
    if values:
        bypass = environ.get("no_proxy") or environ.get("NO_PROXY") or "localhost,127.0.0.1,::1"
        if not isinstance(bypass, str) or any(ord(c) < 32 for c in bypass):
            raise BootstrapProxyError("NO_PROXY 不能包含控制字符")
        values["NO_PROXY"] = bypass
    return values


def _read_state(root):
    if (root / ".deploy").is_symlink():
        raise BootstrapProxyError("部署状态目录不能是符号链接")
    path = root / ".deploy/download-proxy.json"
    if not path.exists() and not path.is_symlink():
        return {}
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384:
        raise BootstrapProxyError("下载代理记录必须属于部署用户且权限为 0600")
    value = json.loads(path.read_text())
    if (value.get("root") != str(root) or not isinstance(value.get("environment"), dict)
            or set(value["environment"]) - {"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"}):
        raise BootstrapProxyError("下载代理记录与当前部署不一致")
    return _proxy_values(value["environment"])


def _write(path, content):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _run(run, command):
    result = run(command, capture_output=True, text=True, check=False, timeout=60)
    if result.returncode:
        raise BootstrapProxyError("首次 Docker 下载代理配置失败；未启动业务服务")
    return result


def _daemon_settings(run, sudo):
    path = "/etc/docker/daemon.json"
    link = run([*sudo, "test", "-L", path], capture_output=True, text=True, check=False, timeout=10)
    if link.returncode != 1:
        raise BootstrapProxyError("Docker daemon 配置不能是符号链接")
    present = run([*sudo, "test", "-e", path], capture_output=True, text=True, check=False, timeout=10)
    if present.returncode == 1:
        data = {}
    elif present.returncode == 0:
        data = json.loads(_run(run, [*sudo, "cat", path]).stdout)
    else:
        raise BootstrapProxyError("无法确认既有 Docker daemon 配置")
    if not isinstance(data, dict) or not isinstance(data.get("registry-mirrors", []), list):
        raise BootstrapProxyError("既有 Docker daemon 配置格式无效")
    mirrors = data.setdefault("registry-mirrors", [])
    if "https://mirror.gcr.io" not in mirrors:
        mirrors.append("https://mirror.gcr.io")
    return data


def prepare_proxy(root, *, environ=None, run=subprocess.run):
    root = Path(root).resolve()
    saved = _read_state(root)
    if saved:
        return saved
    values = _proxy_values(os.environ if environ is None else environ)
    # 已有生产 daemon 不因新的 shell 代理变量而被重启或改写。
    fresh = root / ".deploy/new-local-site.json"
    if not values or not fresh.is_file() or fresh.is_symlink():
        return {}
    if _run(run, ["docker", "ps", "-aq"]).stdout.strip():
        raise BootstrapProxyError("Docker 已有容器，拒绝按首次安装修改 daemon 代理")
    parent = root / ".deploy"
    if parent.is_symlink() or parent.stat().st_uid != os.geteuid():
        raise BootstrapProxyError("部署状态目录不安全")
    source = parent / (".docker-proxy-" + str(os.getpid()))
    unit = source.with_suffix(".conf")
    daemon = source.with_suffix(".json")
    state = parent / "download-proxy.json"
    sudo = [] if os.geteuid() == 0 else ["sudo", "-n"]
    # EnvironmentFile 支持双引号；值中的换行已拒绝，反斜线和引号显式转义。
    content = "".join(name + '="' + value.replace("\\", "\\\\").replace('"', '\\"') + '"\n' for name, value in values.items())
    try:
        _write(source, content)
        _write(unit, "[Service]\nEnvironmentFile=/etc/docker/numericaloj-download-proxy.env\n")
        _write(daemon, json.dumps(_daemon_settings(run, sudo)) + "\n")
        _run(run, [*sudo, "install", "-d", "-m", "0755", "/etc/docker", "/etc/systemd/system/docker.service.d"])
        _run(run, [*sudo, "install", "-o", "root", "-g", "root", "-m", "0600", str(source), "/etc/docker/numericaloj-download-proxy.env"])
        _run(run, [*sudo, "install", "-o", "root", "-g", "root", "-m", "0644", str(unit), "/etc/systemd/system/docker.service.d/numericaloj-download-proxy.conf"])
        _run(run, [*sudo, "install", "-o", "root", "-g", "root", "-m", "0600", str(daemon), "/etc/docker/daemon.json"])
        _run(run, [*sudo, "systemctl", "daemon-reload"])
        _run(run, [*sudo, "systemctl", "restart", "docker"])
        _run(run, ["docker", "info", "--format", "{{.ServerVersion}}"])
        _write(state, json.dumps({"root": str(root), "environment": values}) + "\n")
    finally:
        source.unlink(missing_ok=True)
        unit.unlink(missing_ok=True)
        daemon.unlink(missing_ok=True)
    return values


def build_settings(root):
    values = _read_state(Path(root).resolve())
    # APT/curl 等工具要求小写变量；保留大写以兼容其它下载客户端。
    values = {**values, **{name.lower(): value for name, value in values.items()}}
    # Docker 从当前进程环境读取 build-arg 的值，避免代理凭据出现在 argv 中。
    arguments = ["--network=host"] if values else []
    for name in values:
        arguments.extend(["--build-arg", name])
    return {"environment": values, "build_args": arguments}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "build-settings", "environment", "arguments"))
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command in {"environment", "arguments"}:
            settings = build_settings(args.root)
            items = ([f"{name}={value}" for name, value in settings["environment"].items()]
                     if args.command == "environment" else settings["build_args"])
            for item in items:
                sys.stdout.buffer.write(item.encode() + b"\0")
        else:
            result = prepare_proxy(args.root) if args.command == "prepare" else build_settings(args.root)
            print(json.dumps(result))
    except (BootstrapProxyError, ValueError) as exc:
        parser.exit(1, str(exc) + "\n")


if __name__ == "__main__":
    main()
