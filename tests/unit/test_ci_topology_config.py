"""CI 调用方负责注入网络拓扑，测试入口不得改写 oj_modules/config.py。"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _nested_block(lines: list[str], header: str) -> list[str]:
    start = lines.index(header)
    indent = len(header) - len(header.lstrip())
    block: list[str] = []
    for line in lines[start + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) <= indent:
            break
        block.append(line)
    return block


def _yaml_mapping(lines: list[str], header: str) -> dict[str, str]:
    block = _nested_block(lines, header)
    indent = len(header) - len(header.lstrip()) + 2
    result = {}
    for line in block:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if len(line) - len(line.lstrip()) != indent:
            continue
        key, value = line.strip().split(":", 1)
        result[key] = value.strip().strip('"\'')
    return result


def test_github_integration_uses_runner_service_ports():
    lines = (ROOT / ".github/workflows/ci.yml").read_text(
        encoding="utf-8"
    ).splitlines()
    integration = _nested_block(lines, "  integration:")
    environment = _yaml_mapping(integration, "    env:")

    assert environment["MYSQL_HOST"] == "127.0.0.1"
    assert environment["REDIS_HOST"] == "127.0.0.1"
    assert environment["MYSQL_DB"] == "myojdb_test"
    assert environment["REDIS_DB"] == "15"


def test_compose_test_containers_use_service_dns_names():
    for relative_path in (
        "tests/ci/docker-compose.local.yml",
        "tests/ci/docker-compose.ci.yml",
    ):
        lines = (ROOT / relative_path).read_text(encoding="utf-8").splitlines()
        test_service = _nested_block(lines, "  test:")
        environment = _yaml_mapping(test_service, "    environment:")

        assert environment["MYSQL_HOST"] == "mysql"
        assert environment["REDIS_HOST"] == "redis"
        assert environment["MYSQL_DB"] == "myojdb_test"
        assert environment["REDIS_DB"] == "15"


def test_ci_runner_never_rewrites_tracked_config():
    source = (ROOT / "tests/ci/run-ci.sh").read_text(encoding="utf-8")

    assert "config.ci.py" not in source
    assert "cp oj_modules/config.py" not in source
    assert "cp tests/ci" not in source
    assert "tests/e2e*)" in source
    assert "numericaloj-judger-lite:latest" in source
    assert "numericaloj-agent-judge-lite:latest" in source
