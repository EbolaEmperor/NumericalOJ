#!/usr/bin/env python3
"""为部署构建选择 Docker 官方镜像分发入口，不改动仓库 Dockerfile。"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import urllib.error
import urllib.request


ECR_LIBRARY = "public.ecr.aws/docker/library"
_OFFICIAL_IMAGES = frozenset({
    "alpine", "amazoncorretto", "bash", "busybox", "debian", "docker", "eclipse-temurin",
    "gcc", "golang", "gradle", "httpd", "mariadb", "maven", "memcached", "mongo",
    "mysql", "nginx", "node", "openjdk", "perl", "php", "postgres", "python",
    "rabbitmq", "redis", "registry", "ruby", "rust", "tomcat", "ubuntu",
})
_FROM = re.compile(r"^(\s*FROM\s+)(?:(--platform=\S+\s+))?(\S+)(.*)$", re.IGNORECASE)


class RegistryError(RuntimeError):
    """镜像入口或临时构建文件无法安全确定。"""


def _registry(value):
    value = str(value).strip().rstrip("/")
    if value and not re.fullmatch(r"[a-z0-9][a-z0-9.-]*(?::[0-9]+)?(?:/[a-z0-9][a-z0-9._-]*)+", value):
        raise RegistryError("Docker 官方镜像入口格式无效；应为 registry/path，不含 URL 协议")
    return value


def _safe_parents(root, path):
    if ".." in path.parts or not path.is_relative_to(root):
        raise RegistryError("部署构建文件越出项目目录")
    current = root
    for part in path.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            raise RegistryError("部署构建目录或文件不能是符号链接")


def _write(root, path, text):
    _safe_parents(root, path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp-" + secrets.token_hex(4))
    try:
        with temporary.open("x", encoding="utf-8", newline="") as stream:
            os.chmod(temporary, 0o600)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _probe(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status in (200, 401)
    except urllib.error.HTTPError as exc:
        return exc.code == 401
    except (OSError, urllib.error.URLError):
        return False


def select_registry(root, *, environ=None, probe=None):
    """显式设置与既有部署选择优先；仅在官方 Hub 不可达时自动选 ECR。"""
    root = Path(root).absolute().resolve()
    path = root / ".deploy/docker-library-registry"
    _safe_parents(root, path)
    environ = os.environ if environ is None else environ
    if "NUMOJ_DOCKER_LIBRARY_REGISTRY" in environ:
        value = _registry(environ["NUMOJ_DOCKER_LIBRARY_REGISTRY"])
        _write(root, path, value + "\n")
        return value
    if path.exists():
        metadata = path.stat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise RegistryError("持久镜像入口必须属于部署用户且权限为 0600")
        return _registry(path.read_text(encoding="utf-8"))
    probe = _probe if probe is None else probe
    hub = ("https://registry-1.docker.io/v2/",
           "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/debian:pull")
    if all(probe(url) for url in hub):
        return ""
    ecr = ("https://public.ecr.aws/v2/",
           "https://public.ecr.aws/token/?service=public.ecr.aws&scope=repository:docker/library/debian:pull")
    if all(probe(url) for url in ecr):
        _write(root, path, ECR_LIBRARY + "\n")
        return ECR_LIBRARY
    # 两处均不可达时仍使用既有 Hub 缓存，不臆测第三方镜像源。
    return ""


def rewrite_from(text, registry):
    """仅替换已知官方 library 镜像的 FROM 引用，逐字保留其余构建内容。"""
    registry = _registry(registry)
    if not registry:
        return text
    output, stages = [], set()
    for line in text.splitlines(keepends=True):
        ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
        source = line[:-len(ending)] if ending else line
        match = _FROM.match(source)
        if match:
            image = match.group(3)
            name = re.split(r"[:@]", image, maxsplit=1)[0]
            if name in _OFFICIAL_IMAGES and name.lower() not in stages and "/" not in image and "$" not in image:
                start, end = match.span(3)
                source = source[:start] + registry + "/" + image + source[end:]
            stage = re.match(r"\s+AS\s+([a-zA-Z0-9_.-]+)(?:\s|$)", match.group(4), re.IGNORECASE)
            if stage:
                stages.add(stage.group(1).lower())
        output.append(source + ending)
    return "".join(output)


def prepare_dockerfile(root, source, output, *, registry=None):
    root = Path(root).absolute().resolve()
    source, output = Path(source), Path(output)
    source = source if source.is_absolute() else root / source
    output = output if output.is_absolute() else root / output
    _safe_parents(root, source)
    _safe_parents(root, output)
    destination = root / ".deploy/dockerfiles"
    if not output.is_relative_to(destination) or output == destination or source == output:
        raise RegistryError("临时 Dockerfile 必须写入项目 .deploy/dockerfiles 子目录")
    if not source.is_file():
        raise RegistryError("原始 Dockerfile 不存在")
    registry = select_registry(root) if registry is None else _registry(registry)
    text = source.read_bytes().decode("utf-8")
    _write(root, output, rewrite_from(text, registry))
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("select", "dockerfile"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--source", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == "select":
            print(select_registry(args.root))
        else:
            if args.source is None or args.output is None:
                parser.error("dockerfile 需要 --source 与 --output")
            print(prepare_dockerfile(args.root, args.source, args.output))
        return 0
    except (RegistryError, OSError, UnicodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
