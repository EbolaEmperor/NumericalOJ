"""Single source of truth for supported MySQL/XtraBackup combinations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re


_SERVER_VERSION_RE = re.compile(
    r"^(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)"
    r"(?:[-+~][0-9A-Za-z.+:~_-]+)?$"
)
_PACKAGE_VERSION_SUFFIX_RE = r"(?:[-+~][0-9A-Za-z.+:~_-]+)?"
_REJECTED_VENDOR_MARKERS = (
    "mariadb",
    "aurora",
    "tidb",
    "oceanbase",
    "alloydb",
)


@dataclass(frozen=True)
class ReleaseSpec:
    """One audited server series and its exact XtraBackup release."""

    server_series: str
    minimum_patch: int
    upstream_version: str
    package_name: str
    apt_repository: str

    def accepts_package_version(self, package_version: str) -> bool:
        if not isinstance(package_version, str) or not package_version.strip():
            return False
        escaped = re.escape(self.upstream_version)
        return re.fullmatch(
            rf"(?:[0-9]+:)?{escaped}{_PACKAGE_VERSION_SUFFIX_RE}",
            package_version.strip(),
        ) is not None


XTRABACKUP_RELEASES: Mapping[str, ReleaseSpec] = {
    "8.0": ReleaseSpec(
        server_series="8.0",
        minimum_patch=34,
        upstream_version="8.0.35-36",
        package_name="percona-xtrabackup-80",
        apt_repository="pxb-80",
    ),
    "8.4": ReleaseSpec(
        server_series="8.4",
        minimum_patch=0,
        upstream_version="8.4.0-6",
        package_name="percona-xtrabackup-84",
        apt_repository="pxb-84-lts",
    ),
}


def detect_server_vendor(server_version: str, version_comment: str) -> str | None:
    """Recognize only Oracle MySQL and Percona Server, failing closed."""

    if not isinstance(server_version, str) or not isinstance(version_comment, str):
        return None
    version = server_version.strip().lower()
    comment = version_comment.strip().lower()
    if not version or not comment:
        return None
    combined = f"{version} {comment}"
    if any(marker in combined for marker in _REJECTED_VENDOR_MARKERS):
        return None
    if "percona server" in combined:
        return "percona"
    if (
        re.search(r"\bmysql (?:community|enterprise) server\b", comment)
        or comment == "mysql"
        or "oracle mysql" in comment
    ):
        return "oracle_mysql"
    return None


def select_release(
    server_version: str,
    version_comment: str,
) -> ReleaseSpec | None:
    """Map server-reported facts to one fixed release, never by client version."""

    if not isinstance(server_version, str):
        return None
    match = _SERVER_VERSION_RE.fullmatch(server_version.strip())
    if match is None or detect_server_vendor(server_version, version_comment) is None:
        return None
    major, minor, patch = (
        int(match.group(name)) for name in ("major", "minor", "patch")
    )
    release = XTRABACKUP_RELEASES.get(f"{major}.{minor}")
    if release is None or patch < release.minimum_patch:
        return None
    return release
