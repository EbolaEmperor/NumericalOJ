"""作品 GPU 申请及宿主显存监测。显存限制为超限回收，不是硬隔离。"""

from __future__ import annotations

import json
import re

from backend.oj_modules.infrastructure.mysql import get_db_connection

MAX_MEMORY_MIB = 24 * 1024
MIN_MEMORY_MIB = 256
GPU_UUID_RE = re.compile(r"GPU-[0-9a-fA-F-]{36}")


class GPUError(RuntimeError):
    """只包含可公开的 GPU 状态信息。"""


def memory_limit(value) -> int:
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)):
        raise GPUError("GPU 显存额度必须为整数 MiB，0 表示不使用 GPU")
    limit = int(value)
    if limit != 0 and not MIN_MEMORY_MIB <= limit <= MAX_MEMORY_MIB:
        raise GPUError("GPU 显存额度必须在 256–24576 MiB 之间")
    return limit


def manifest_policy(raw) -> tuple[int, int]:
    try:
        manifest = json.loads(raw or "{}") if isinstance(raw, (str, type(None))) else raw
        if not isinstance(manifest, dict):
            raise ValueError
        requested = memory_limit(manifest.get("gpu_memory_mib", 0))
        approved = memory_limit(manifest.get("gpu_approved_memory_mib", 0))
        if approved > requested:
            raise ValueError
        return requested, approved
    except (ValueError, TypeError) as exc:
        raise GPUError("作品 GPU 配置无效，请联系管理员") from exc


def set_request(manifest: dict, metadata: dict, *, previous=None) -> None:
    # 上传包不能授予权限；每个新版本都清除批准值，只继承申请值。
    inherited, _ = manifest_policy(previous)
    requested = memory_limit(metadata.get("gpu_memory_mib", inherited))
    manifest.pop("gpu_memory_mib", None)
    manifest.pop("gpu_approved_memory_mib", None)
    if requested:
        manifest["gpu_memory_mib"] = requested


def invalid_allocations(runtimes: dict) -> set[str]:
    """批量核对当前版本及额度；撤权、换版后旧租约不能继续占用 GPU。"""
    ids = sorted({int(item["gpu"]["version_id"]) for item in runtimes.values()})
    if not ids:
        return set()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT p.slug, p.latest_version_id, p.review_version_id, p.public_version_id, "
                "v.id, v.review_status, v.manifest_json FROM vibehub_versions v "
                "JOIN vibehub_projects p ON p.id = v.project_id "
                "WHERE v.id IN (" + ",".join(["%s"] * len(ids)) + ")",
                tuple(ids),
            )
            rows = {int(row["id"]): row for row in cursor.fetchall() or []}
    finally:
        conn.close()
    invalid = set()
    for runtime_id, item in runtimes.items():
        allocation = item["gpu"]
        row = rows.get(int(allocation["version_id"]))
        channel = item["channel"]
        if not row or row["slug"] != item["project_key"]:
            invalid.add(runtime_id)
            continue
        requested, approved = manifest_policy(row["manifest_json"])
        version_id = int(row["id"])
        current_id = row.get(f"{channel}_version_id")
        if current_id != version_id:
            invalid.add(runtime_id)
            continue
        limit = approved if row["review_status"] == "approved" else 0
        if channel != "public" and row["review_status"] == "pending" and row.get("review_version_id") == version_id:
            limit = requested
        if not limit or limit != allocation["memory_mib"]:
            invalid.add(runtime_id)
    return invalid


def _run(cli, args) -> str:
    result = cli._run(args, timeout=3)
    if result.returncode:
        raise GPUError("GPU 监测不可用，暂时无法运行 GPU 作品")
    return result.stdout.strip()


def device(cli, limit: int) -> str:
    output = _run(cli, ["nvidia-smi", "--id=0", "--query-gpu=uuid,memory.total", "--format=csv,noheader,nounits"])
    try:
        uuid, total = (part.strip() for part in output.split(","))
        if not GPU_UUID_RE.fullmatch(uuid) or int(total) <= 0 or ((int(total) + 1023) // 1024) * 1024 < limit:
            raise ValueError
    except ValueError as exc:
        raise GPUError("GPU 不可用或申请显存超过设备容量") from exc
    return uuid


def usage(cli, runtimes: dict) -> dict[str, int]:
    """从 Docker 宿主 PID 与宿主 nvidia-smi 汇总，作品不能自行上报用量。"""
    pids = {}
    for runtime_id, item in runtimes.items():
        name = item["container_name"]
        if not re.fullmatch(r"numoj-vh-[0-9a-f]{16}-[0-9a-f]{40}", name):
            raise GPUError("GPU 容器身份无效")
        if not cli.container_running(name):
            pids[runtime_id] = set()
            continue
        rows = _run(cli, ["docker", "top", name, "-eo", "pid"]).splitlines()
        if not rows or rows[0].strip() != "PID":
            raise GPUError("GPU 进程监测不可用")
        try:
            pids[runtime_id] = {int(line.strip()) for line in rows[1:]}
        except ValueError as exc:
            raise GPUError("GPU 进程监测不可用") from exc
    output = _run(cli, ["nvidia-smi", "--query-compute-apps=gpu_uuid,pid,used_gpu_memory", "--format=csv,noheader,nounits"])
    processes = {}
    for line in output.splitlines():
        try:
            uuid, pid, memory = (part.strip() for part in line.split(","))
            if not GPU_UUID_RE.fullmatch(uuid) or int(memory) < 0:
                raise ValueError
            key = (uuid, int(pid))
            processes[key] = processes.get(key, 0) + int(memory)
        except ValueError as exc:
            raise GPUError("GPU 显存监测不可用") from exc
    return {
        runtime_id: sum(processes.get((item["gpu"]["device"], pid), 0) for pid in pids[runtime_id])
        for runtime_id, item in runtimes.items()
    }


def over_limit_projects(runtimes: dict, memory: dict[str, int]) -> set[str]:
    totals, limits, exceeded = {}, {}, set()
    for runtime_id, item in runtimes.items():
        project = item["project_key"]
        limit = item["gpu"]["memory_mib"]
        used = memory[runtime_id]
        totals[project] = totals.get(project, 0) + used
        # 同一作品新旧版本并存时按其中较高的有效额度合计；每个版本仍受自己的额度约束。
        limits[project] = max(limits.get(project, 0), limit)
        if used > limit:
            exceeded.add(project)
    return exceeded | {project for project, total in totals.items() if total > limits[project]}
