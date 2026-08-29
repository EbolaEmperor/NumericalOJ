from scripts import benchmark_http
from scripts.benchmark_http import _is_loopback_host, _percentile, run_benchmark


class _Response:
    status = 200
    will_close = False

    def read(self):
        return b"ok"

    def getheader(self, name):
        return {
            "Content-Encoding": None,
            "Cache-Control": "public, max-age=60",
        }.get(name)


class _Connection:
    def request(self, method, target, headers):
        assert method == "GET"
        assert target == "/health/live"
        assert headers["Accept-Encoding"] == "gzip, br"

    def getresponse(self):
        return _Response()

    def close(self):
        return None


def test_percentile_uses_nearest_rank():
    assert _percentile([1, 2, 3, 4, 5], 50) == 3
    assert _percentile([1, 2, 3, 4, 5], 95) == 5
    assert _percentile([], 95) is None


def test_cli_loopback_guard_does_not_resolve_arbitrary_hosts():
    assert _is_loopback_host("127.0.0.1") is True
    assert _is_loopback_host("::1") is True
    assert _is_loopback_host("localhost") is True
    assert _is_loopback_host("computing") is False


def test_http_benchmark_reports_concurrency_status_and_headers(monkeypatch):
    monkeypatch.setattr(
        benchmark_http,
        "_new_connection",
        lambda *_args, **_kwargs: _Connection(),
    )
    summary = run_benchmark(
        "http://127.0.0.1:2025/health/live",
        requests=20,
        concurrency=5,
        timeout_seconds=2,
    )

    assert summary["requests"] == 20
    assert summary["concurrency"] == 5
    assert summary["status_counts"] == {"200": 20}
    assert summary["transport_error_count"] == 0
    assert summary["content_encoding_counts"] == {"identity": 20}
    assert summary["cache_control_counts"] == {"public, max-age=60": 20}
    assert summary["response_body_bytes"] == {"total": 40, "mean": 2.0}
    assert summary["latency_ms"]["ttfb"]["p95"] is not None


def test_cli_defaults_to_256_concurrent_connections(monkeypatch, capsys):
    calls = []

    def fake_run(_url, **settings):
        calls.append(settings)
        return {
            "requests": settings["requests"],
            "concurrency": settings["concurrency"],
            "requests_per_second": 1.0,
            "status_counts": {"200": settings["requests"]},
            "transport_error_count": 0,
            "transport_errors": {},
            "content_encoding_counts": {"identity": settings["requests"]},
            "cache_control_counts": {"<missing>": settings["requests"]},
            "response_body_bytes": {"total": 0, "mean": 0.0},
            "latency_ms": {
                "ttfb": {
                    "p50": 1.0,
                    "p90": 1.0,
                    "p95": 1.0,
                    "p99": 1.0,
                    "max": 1.0,
                },
                "total": {
                    "p50": 1.0,
                    "p90": 1.0,
                    "p95": 1.0,
                    "p99": 1.0,
                    "max": 1.0,
                },
            },
        }

    monkeypatch.setattr(benchmark_http, "run_benchmark", fake_run)

    assert benchmark_http.main([
        "http://127.0.0.1:2025/health/live",
        "--warmup",
        "0",
    ]) == 0
    assert calls[0]["concurrency"] == 256
    capsys.readouterr()
