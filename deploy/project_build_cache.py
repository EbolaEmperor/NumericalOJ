#!/usr/bin/env python3
"""低磁盘开发部署只回收已完成候选镜像的精确私有 BuildKit 缓存记录。"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.backup import container_client, development  # noqa: E402
from deploy.backup.paths import assert_no_symlink_components, ensure_directory  # noqa: E402
from deploy.bootstrap import _load_config  # noqa: E402
from scripts.mysql_admin import settings_from_config  # noqa: E402

LOW_DISK_BYTES = 64 * 1024**3
MIN_FREE_BYTES = development.RESERVE_BYTES
MANAGED_LABEL = "org.numericaloj.deploy-managed"
SOURCE_LABEL = "org.numericaloj.source-sha256"  # 仅读取既有标签，不计算文件指纹。
SPECS = {
    "numericaloj-judger": ("/sandbox", ("texlive-full", "intel-oneapi-mkl-devel")),
    "numericaloj-lean4": ("/sandbox", ("elan-init.sh", "lake exe cache get", "numoj-lean-verifier")),
    "numericaloj-agent-judge": ("/workspace", ("torch torchvision", "paddlepaddle paddleocr", "pi-coding-agent", "run_harness")),
}
_ID = re.compile(r"[a-z0-9]{12,64}")


class CacheReclamationError(RuntimeError):
    pass


def _run(arguments, run):
    result = run([container_client._docker(), *arguments], capture_output=True, text=True,
                 check=False, timeout=120, env=container_client.docker_environment())
    if result.returncode:
        raise CacheReclamationError(f"Docker 缓存检查或回收失败（退出码 {result.returncode}）")
    if len(result.stdout) > 32 * 1024**2:
        raise CacheReclamationError("Docker 缓存元数据超过安全读取上限")
    return result.stdout


def read_records(builder, run):
    rows = [json.loads(line) for line in _run(["buildx", "du", "--builder", builder, "--format=json"], run).splitlines() if line.strip()]
    records = {}
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get("ID"), str) or not _ID.fullmatch(row["ID"])
                or row["ID"] in records or "Parents" not in row or not isinstance(row.get("Description"), str)):
            raise CacheReclamationError("BuildKit 缓存图包含未知或重复记录")
        parents = [] if row["Parents"] is None else row["Parents"]
        if not isinstance(parents, list) or any(not isinstance(parent, str) or not _ID.fullmatch(parent) for parent in parents):
            raise CacheReclamationError("BuildKit 缓存父记录无效")
        records[row["ID"]] = dict(row, Parents=parents)
    return records


def _children(records):
    children = {identifier: set() for identifier in records}
    for identifier, row in records.items():
        for parent in row["Parents"]:
            children.setdefault(parent, set()).add(identifier)
    return children


def _closure(leaf, records):
    pending, found, visiting = [(leaf, False)], set(), set()
    while pending:
        identifier, finished = pending.pop()
        if finished:
            visiting.remove(identifier)
            found.add(identifier)
            continue
        if identifier in found:
            continue
        if identifier in visiting or identifier not in records:
            return None
        visiting.add(identifier)
        pending.append((identifier, True))
        pending.extend((parent, False) for parent in records[identifier]["Parents"])
    return found


def _eligible(row, own_source=False):
    return (row.get("Reclaimable") is True and row.get("Shared") is False
            and row.get("Mutable") is False and row.get("Type") == "regular"
            and (own_source or not row["Description"].startswith("pulled from ")))


def _closed_selection(records, allowed, own_sources=frozenset()):
    children = _children(records)
    selected = {identifier for identifier in allowed if identifier in records and _eligible(records[identifier], identifier in own_sources)}
    while True:
        reduced = {identifier for identifier in selected if children[identifier] <= selected}
        if reduced == selected:
            return selected
        selected = reduced


def select_records(records, images=None):
    """唯一终点和独特祖先定位归属；任何链外使用都会阻止相应祖先回收。"""
    allowed, chains = set(), {}
    for repository, (workdir, markers) in SPECS.items():
        matches = []
        for identifier, row in records.items():
            if not re.search(r"(?:^|\]\s+)WORKDIR " + re.escape(workdir) + r"$", row["Description"]):
                continue
            closure = _closure(identifier, records)
            if closure and all(any(marker in records[parent]["Description"] for parent in closure) for marker in markers):
                matches.append((identifier, closure))
        if len(matches) != 1:
            chains[repository] = {"skipped": "终点缺失、祖先不明或归属不唯一", "matching_leaves": [leaf for leaf, _ in matches]}
            continue
        leaf, closure = matches[0]
        allowed.update(closure)
        chains[repository] = {"leaf": leaf, "markers": list(markers), "record_ids": sorted(closure)}
    # 内部 Lean image source 只有同时绑定当前候选标签与 Docker engine ID
    # 才能随项目链回收；普通公共 pulled base 永远保留。
    own_sources = set()
    lean = (images or {}).get("numericaloj-lean4")
    if lean and "leaf" in chains["numericaloj-lean4"]:
        expected = f"pulled from {lean['reference']}@{lean['image_id']}"
        for identifier, row in records.items():
            if row["Description"] == expected:
                closure = _closure(identifier, records)
                if closure and set(row["Parents"]) <= set(chains["numericaloj-lean4"]["record_ids"]):
                    own_sources.add(identifier)
                    allowed.add(identifier)
    selected = _closed_selection(records, allowed, own_sources)
    children, remaining, ordered = _children(records), set(selected), []
    while remaining:
        leaves = sorted(identifier for identifier in remaining if not children[identifier] & remaining)
        if not leaves:
            raise CacheReclamationError("BuildKit 缓存图存在循环，禁止回收")
        ordered.extend(leaves)
        remaining.difference_update(leaves)
    blocked = {identifier: sorted(children[identifier] - selected) for identifier in allowed - selected
               if children[identifier] - selected}
    return ordered, {"chains": chains, "bound_lean_source_ids": sorted(own_sources), "blocked_children": blocked}


def _candidates(references, run):
    if len(references) != 3 or len(set(references)) != 3:
        raise CacheReclamationError("必须提供三个不同的完整候选镜像")
    images = {}
    for reference in references:
        match = re.fullmatch(r"(numericaloj-(?:judger|lean4|agent-judge)):deploy-[A-Za-z0-9_.-]+", reference)
        if not match or match[1] in images:
            raise CacheReclamationError("候选镜像不属于固定项目仓库")
        payload = json.loads(_run(["image", "inspect", reference], run))
        if not isinstance(payload, list) or len(payload) != 1:
            raise CacheReclamationError("候选镜像检查结果不唯一")
        image = payload[0]
        labels = (image.get("Config") or {}).get("Labels") or {}
        source = labels.get(SOURCE_LABEL)
        if (labels.get(MANAGED_LABEL) != "true" or not isinstance(source, str) or not source.strip()
                or not isinstance(image.get("Id"), str) or not image["Id"]
                or reference not in (image.get("RepoTags") or [])):
            raise CacheReclamationError("候选镜像尚未完成或缺少项目归属标签")
        images[match[1]] = {"reference": reference, "image_id": image["Id"], "source_label": source}
    if set(images) != set(SPECS):
        raise CacheReclamationError("完整候选仓库集合不匹配")
    return images


def _disk_root(builder, facts, run):
    info = json.loads(_run(["info", "--format", "{{json .}}"], run))
    if not isinstance(info, dict):
        raise CacheReclamationError("Docker 数据目录信息无效")
    path = assert_no_symlink_components(info.get("DockerRootDir", ""), label="Docker 数据目录")
    if not path.is_dir():
        raise CacheReclamationError("Docker 数据目录不可确认")
    if ["driver-type", "io.containerd.snapshotter.v1"] in info.get("DriverStatus", []):
        containerd = assert_no_symlink_components("/var/lib/containerd", label="containerd 数据目录")
        if not containerd.is_dir() or containerd.stat().st_dev != path.stat().st_dev:
            raise CacheReclamationError("Docker 与 containerd 不在同一可确认文件系统")
    details = json.loads(_run(["buildx", "inspect", builder, "--format", "{{json .}}"], run))
    if not isinstance(details, dict):
        raise CacheReclamationError("builder 信息无效")
    nodes = details.get("Nodes") or []
    if details.get("Driver") != "docker" or not isinstance(nodes, list) or len(nodes) != 1 or not isinstance(nodes[0], dict):
        raise CacheReclamationError("只允许单节点本机 Docker builder")
    endpoint = nodes[0].get("Endpoint")
    if endpoint != facts["docker_endpoint"]:
        if not isinstance(endpoint, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", endpoint):
            raise CacheReclamationError("无法确认 builder 的本机 endpoint")
        endpoint = json.loads(_run(["context", "inspect", endpoint, "--format", "{{json .Endpoints.docker.Host}}"], run))
    if endpoint != facts["docker_endpoint"]:
        raise CacheReclamationError("builder 与已核验的本机 Docker endpoint 不一致")
    return path


def _free_bytes(path):
    info = os.statvfs(path)
    return info.f_bavail * info.f_frsize


def _audit_writer(root):
    directory = ensure_directory(root / ".deploy/build-cache", label="项目缓存审计")
    metadata = directory.stat()
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise CacheReclamationError("项目缓存审计目录必须属于部署用户且权限为0700")
    path = directory / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4) + ".json")

    def write(value):
        temporary = path.with_suffix(".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(value, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    return path, write


def reclaim(root, builder, references, *, config=None, run=subprocess.run):
    root = Path(root).absolute()
    try:
        settings = settings_from_config(config if config is not None else _load_config(root))
        facts = development.reserve_facts(root, settings)
    except (RuntimeError, OSError, ValueError):
        return {"status": "skipped", "reason": "不符合完整本机开发测试库条件"}
    if not isinstance(builder, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", builder):
        return {"status": "skipped", "reason": "builder名称不可确认"}
    try:
        disk = _disk_root(builder, facts, run)
        before = _free_bytes(disk)
        if before >= LOW_DISK_BYTES:
            return {"status": "skipped", "reason": "磁盘空间充足", "free_bytes": before}
        images = _candidates(references, run)
        records = read_records(builder, run)
        selected, provenance = select_records(records, images)
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError):
        return {"status": "skipped", "reason": "镜像归属、缓存图或文件系统不可可靠确认"}
    path, write = _audit_writer(root)
    audit = {"facts": facts, "builder": builder, "candidates": images, "disk_root": str(disk),
             "free_bytes_before": before, "selected_ids": selected, **provenance, "actions": [],
             "graph": [{key: row.get(key) for key in ("ID", "Parents", "Reclaimable", "Shared", "Mutable", "Type")}
                       for row in records.values()], "status": "planned"}
    write(audit)
    remaining = set(selected)
    disk_device = disk.stat().st_dev
    try:
        for identifier in selected:
            if _free_bytes(disk) >= LOW_DISK_BYTES:
                break
            if development.reserve_facts(root, settings) != facts or _candidates(references, run) != images:
                raise CacheReclamationError("回收前开发环境或候选镜像身份发生变化")
            if _disk_root(builder, facts, run) != disk or disk.stat().st_dev != disk_device:
                raise CacheReclamationError("回收前 Docker 数据文件系统发生变化")
            current = read_records(builder, run)
            same_records = {item for item in remaining if item in current
                            and all(current[item][key] == records[item][key] for key in ("Parents", "Description", "Type"))}
            eligible = _closed_selection(current, same_records, set(provenance["bound_lean_source_ids"]))
            if identifier not in eligible:
                audit["actions"].append({"id": identifier, "status": "skipped", "reason": "刷新后仍被使用、归属变化或出现链外child"})
                remaining.discard(identifier)
                write(audit)
                continue
            # Buildx 把 id= 转为正则，因此必须锚定完整 ID；布尔属性用存在性匹配。
            # 官方 BuildKit prune 在锁内跳过所有仍持有 refs 的记录，保护刷新后的租约竞态。
            # https://github.com/docker/buildx/blob/v0.30.1/commands/prune.go#L215
            # https://github.com/moby/buildkit/blob/v0.26.0/cache/manager.go#L1074
            command = ["buildx", "prune", "--builder", builder, "--force", "--filter", f"id=^{identifier}$",
                       "--filter", "immutable=", "--filter", "private=",
                       "--filter", "type=regular"]
            audit["actions"].append({"id": identifier, "status": "requested", "command": command})
            write(audit)
            _run(command, run)
            after = read_records(builder, run)
            audit["actions"][-1]["status"] = "retained" if identifier in after else "completed"
            remaining.discard(identifier)
            write(audit)
        audit["free_bytes_after"] = _free_bytes(disk)
        if audit["free_bytes_after"] < MIN_FREE_BYTES:
            raise CacheReclamationError("项目精确缓存回收后磁盘不足2GiB，已停止部署")
        audit["status"] = "completed" if any(action["status"] == "completed" for action in audit["actions"]) else "skipped"
        return {"status": audit["status"], "audit_path": str(path), "free_bytes": audit["free_bytes_after"],
                "reclaimed_ids": [action["id"] for action in audit["actions"] if action["status"] == "completed"]}
    except BaseException as error:
        audit.update(status="failed", error=str(error))
        raise
    finally:
        write(audit)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--builder", default="default")
    parser.add_argument("--candidate", action="append", required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(reclaim(args.root, args.builder, args.candidate), ensure_ascii=False))
        return 0
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"项目缓存回收失败：{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
