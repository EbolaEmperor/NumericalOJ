#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""对 NumericalOJ HTTP 入口执行无外部依赖的并发延迟基准。

只发送只读 GET；认证页面可通过权限受限的 header 文件注入 Cookie。工具同时统计
TTFB 与完整响应耗时，并回显 Content-Encoding / Cache-Control 分布，便于区分
应用查询、响应压缩和静态资源缓存问题。
"""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import http.client
import ipaddress
import json
import math
from pathlib import Path
import queue
import ssl
import threading
import time
from urllib.parse import urlsplit


@dataclass(frozen=True)
class _Target:
    scheme: str
    host: str
    port: int
    request_target: str


@dataclass(frozen=True)
class _Sample:
    status: int | None
    ttfb_ms: float | None
    total_ms: float
    body_bytes: int
    content_encoding: str
    cache_control: str
    error: str | None = None


def _parse_target(url: str) -> _Target:
    parsed = urlsplit(str(url).strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("URL 只支持 http:// 或 https://")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("URL 必须包含主机，且不能包含用户名或密码")
    if parsed.fragment:
        raise ValueError("URL 不能包含 fragment")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("URL 端口无效") from exc
    request_target = parsed.path or "/"
    if parsed.query:
        request_target = f"{request_target}?{parsed.query}"
    return _Target(parsed.scheme, parsed.hostname, port, request_target)


def _is_loopback_host(host: str) -> bool:
    value = str(host or "").strip().lower()
    if value == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil((percentile / 100.0) * len(ordered)))
    return round(ordered[min(rank, len(ordered)) - 1], 3)


def _latency_summary(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"p50": None, "p90": None, "p95": None, "p99": None, "max": None}
    return {
        "p50": _percentile(values, 50),
        "p90": _percentile(values, 90),
        "p95": _percentile(values, 95),
        "p99": _percentile(values, 99),
        "max": round(max(values), 3),
    }


def _new_connection(
    target: _Target,
    *,
    timeout_seconds: float,
    insecure_https: bool,
):
    if target.scheme == "https":
        context = ssl._create_unverified_context() if insecure_https else ssl.create_default_context()
        return http.client.HTTPSConnection(
            target.host,
            target.port,
            timeout=timeout_seconds,
            context=context,
        )
    return http.client.HTTPConnection(
        target.host,
        target.port,
        timeout=timeout_seconds,
    )


def run_benchmark(
    url: str,
    *,
    requests: int,
    concurrency: int,
    timeout_seconds: float = 5.0,
    headers: dict[str, str] | None = None,
    keepalive: bool = True,
    insecure_https: bool = False,
) -> dict:
    """执行 GET 基准并返回可 JSON 序列化的汇总，不修改服务端状态。"""
    target = _parse_target(url)
    request_count = int(requests)
    worker_count = min(int(concurrency), request_count)
    if request_count <= 0:
        raise ValueError("requests 必须为正整数")
    if worker_count <= 0:
        raise ValueError("concurrency 必须为正整数")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds 必须为正数")

    request_headers = {
        "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, br",
        "User-Agent": "NumericalOJ-HTTP-Benchmark/1",
        "Connection": "keep-alive" if keepalive else "close",
        **(headers or {}),
    }
    work = queue.SimpleQueue()
    for index in range(request_count):
        work.put(index)
    start_gate = threading.Barrier(worker_count)

    def worker():
        local_samples = []
        connection = None
        start_gate.wait()
        try:
            while True:
                try:
                    work.get_nowait()
                except queue.Empty:
                    break
                if connection is None:
                    connection = _new_connection(
                        target,
                        timeout_seconds=float(timeout_seconds),
                        insecure_https=insecure_https,
                    )
                started = time.perf_counter()
                try:
                    connection.request("GET", target.request_target, headers=request_headers)
                    response = connection.getresponse()
                    headers_received = time.perf_counter()
                    body = response.read()
                    finished = time.perf_counter()
                    local_samples.append(_Sample(
                        status=int(response.status),
                        ttfb_ms=(headers_received - started) * 1000,
                        total_ms=(finished - started) * 1000,
                        body_bytes=len(body),
                        content_encoding=(response.getheader("Content-Encoding") or "identity").lower(),
                        cache_control=response.getheader("Cache-Control") or "<missing>",
                    ))
                    if not keepalive or response.will_close:
                        connection.close()
                        connection = None
                except Exception as exc:
                    finished = time.perf_counter()
                    local_samples.append(_Sample(
                        status=None,
                        ttfb_ms=None,
                        total_ms=(finished - started) * 1000,
                        body_bytes=0,
                        content_encoding="<transport-error>",
                        cache_control="<transport-error>",
                        error=f"{type(exc).__name__}: {str(exc)[:200]}",
                    ))
                    try:
                        connection.close()
                    except Exception:
                        pass
                    connection = None
        finally:
            if connection is not None:
                connection.close()
        return local_samples

    wall_started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [executor.submit(worker) for _ in range(worker_count)]
        samples = [sample for future in futures for sample in future.result()]
    wall_seconds = time.perf_counter() - wall_started

    ttfb_values = [sample.ttfb_ms for sample in samples if sample.ttfb_ms is not None]
    total_values = [sample.total_ms for sample in samples]
    statuses = Counter(str(sample.status) for sample in samples if sample.status is not None)
    encodings = Counter(sample.content_encoding for sample in samples)
    cache_controls = Counter(sample.cache_control for sample in samples)
    errors = Counter(sample.error for sample in samples if sample.error)
    total_body_bytes = sum(sample.body_bytes for sample in samples)
    return {
        "url": url,
        "requests": request_count,
        "concurrency": worker_count,
        "keepalive": bool(keepalive),
        "wall_seconds": round(wall_seconds, 6),
        "requests_per_second": round(len(samples) / wall_seconds, 3),
        "status_counts": dict(sorted(statuses.items())),
        "transport_error_count": sum(errors.values()),
        "transport_errors": dict(errors.most_common(5)),
        "content_encoding_counts": dict(sorted(encodings.items())),
        "cache_control_counts": dict(sorted(cache_controls.items())),
        "response_body_bytes": {
            "total": total_body_bytes,
            "mean": round(total_body_bytes / len(samples), 3),
        },
        "latency_ms": {
            "ttfb": _latency_summary(ttfb_values),
            "total": _latency_summary(total_values),
        },
    }


def _read_header_file(path: str | None) -> dict[str, str]:
    if not path:
        return {}
    headers = {}
    for line_number, raw_line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise ValueError(f"header 文件第 {line_number} 行缺少冒号")
        name, value = line.split(":", 1)
        name = name.strip()
        if not name or any(char.isspace() for char in name):
            raise ValueError(f"header 文件第 {line_number} 行名称无效")
        if "\r" in value or "\n" in value:
            raise ValueError(f"header 文件第 {line_number} 行包含换行")
        headers[name] = value.strip()
    return headers


def _format_ms(value):
    return "n/a" if value is None else f"{value:.3f} ms"


def _print_human(summary: dict) -> None:
    latency = summary["latency_ms"]
    print(
        f"完成 {summary['requests']} 请求 / 并发 {summary['concurrency']} / "
        f"{summary['requests_per_second']:.1f} req/s"
    )
    print(
        "TTFB  "
        f"p50={_format_ms(latency['ttfb']['p50'])} "
        f"p95={_format_ms(latency['ttfb']['p95'])} "
        f"p99={_format_ms(latency['ttfb']['p99'])}"
    )
    print(
        "完整  "
        f"p50={_format_ms(latency['total']['p50'])} "
        f"p95={_format_ms(latency['total']['p95'])} "
        f"p99={_format_ms(latency['total']['p99'])}"
    )
    print(f"状态码: {summary['status_counts']}；传输错误: {summary['transport_error_count']}")
    print(f"压缩: {summary['content_encoding_counts']}")
    print(f"缓存: {summary['cache_control_counts']}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="NumericalOJ 只读 HTTP 并发延迟基准")
    parser.add_argument("url", help="完整的 http(s) URL")
    parser.add_argument("-n", "--requests", type=int, default=1000, help="正式请求数（默认 1000）")
    parser.add_argument("-c", "--concurrency", type=int, default=256, help="并发连接数（默认 256）")
    parser.add_argument("--warmup", type=int, default=50, help="正式统计前的预热请求数（默认 50）")
    parser.add_argument("--timeout", type=float, default=5.0, help="单请求超时秒数（默认 5）")
    parser.add_argument("--header-file", help="逐行 Name: Value；可用于从权限受限文件读取 Cookie")
    parser.add_argument("--no-keepalive", action="store_true", help="每次请求重新建连")
    parser.add_argument("--insecure", action="store_true", help="HTTPS 不校验证书，仅限可信测试环境")
    parser.add_argument(
        "--allow-non-loopback-test-host",
        action="store_true",
        help="仅对明确隔离的非回环测试服务启用；生产禁止使用",
    )
    parser.add_argument("--expect-status", type=int, action="append", default=[200], help="允许的状态码，可重复")
    parser.add_argument("--max-p95-ttfb-ms", type=float, help="TTFB p95 超过该值时退出 1")
    parser.add_argument("--max-p95-total-ms", type=float, help="完整响应 p95 超过该值时退出 1")
    parser.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    args = parser.parse_args(argv)

    try:
        target = _parse_target(args.url)
    except ValueError as exc:
        parser.error(str(exc))
    if (
        not args.allow_non_loopback_test_host
        and not _is_loopback_host(target.host)
    ):
        parser.error(
            "默认只允许回环测试地址；隔离测试网络需显式使用 "
            "--allow-non-loopback-test-host，生产禁止运行"
        )

    try:
        headers = _read_header_file(args.header_file)
        if args.warmup > 0:
            run_benchmark(
                args.url,
                requests=args.warmup,
                concurrency=min(args.concurrency, args.warmup),
                timeout_seconds=args.timeout,
                headers=headers,
                keepalive=not args.no_keepalive,
                insecure_https=args.insecure,
            )
        summary = run_benchmark(
            args.url,
            requests=args.requests,
            concurrency=args.concurrency,
            timeout_seconds=args.timeout,
            headers=headers,
            keepalive=not args.no_keepalive,
            insecure_https=args.insecure,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    if args.json:
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    else:
        _print_human(summary)

    expected = {str(status) for status in args.expect_status}
    unexpected = {
        status: count
        for status, count in summary["status_counts"].items()
        if status not in expected
    }
    failed = summary["transport_error_count"] > 0 or bool(unexpected)
    ttfb_p95 = summary["latency_ms"]["ttfb"]["p95"]
    total_p95 = summary["latency_ms"]["total"]["p95"]
    if args.max_p95_ttfb_ms is not None and (
        ttfb_p95 is None or ttfb_p95 > args.max_p95_ttfb_ms
    ):
        failed = True
    if args.max_p95_total_ms is not None and (
        total_p95 is None or total_p95 > args.max_p95_total_ms
    ):
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
