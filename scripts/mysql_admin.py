"""Shared MySQL configuration and connection primitives for admin scripts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_]+$")


@dataclass(frozen=True)
class MySQLSettings:
    host: str
    port: int
    user: str
    password: str
    database: str
    connect_timeout: int


def load_config():
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    import config  # noqa: WPS433

    return config


def database_name_from_config(config) -> str:
    database = str(getattr(config, "MYSQL_DB", "myojdb"))
    if not IDENTIFIER_RE.fullmatch(database):
        raise ValueError(f"invalid database name: {database!r}")
    return database


def database_exists(cursor, database: str) -> bool:
    cursor.execute(
        "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA "
        "WHERE SCHEMA_NAME=%s",
        (database,),
    )
    return cursor.fetchone() is not None


def settings_from_config(config=None) -> MySQLSettings:
    config = config or load_config()
    return MySQLSettings(
        host=str(getattr(config, "MYSQL_HOST", "127.0.0.1")),
        port=int(getattr(config, "MYSQL_PORT", 3306)),
        user=str(getattr(config, "MYSQL_USERNAME")),
        password=str(getattr(config, "MYSQL_PASSWORD")),
        database=database_name_from_config(config),
        connect_timeout=int(getattr(config, "MYSQL_CONNECT_TIMEOUT", 5)),
    )


def connect_mysql(
    settings: MySQLSettings,
    *,
    with_database: bool,
    dict_rows: bool = False,
):
    import pymysql  # noqa: WPS433

    kwargs = {
        "host": settings.host,
        "port": settings.port,
        "user": settings.user,
        "password": settings.password,
        "charset": "utf8mb4",
        "connect_timeout": settings.connect_timeout,
        "autocommit": False,
    }
    if with_database:
        kwargs["database"] = settings.database
    if dict_rows:
        kwargs["cursorclass"] = pymysql.cursors.DictCursor
    return pymysql.connect(**kwargs)
