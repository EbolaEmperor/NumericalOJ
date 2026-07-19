#!/usr/bin/env python3
"""Create an atomic, compressed backup of the configured MySQL database."""

from __future__ import annotations

import argparse
import gzip
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.mysql_admin import (  # noqa: E402
    MySQLSettings,
    connect_mysql,
    database_exists,
    settings_from_config,
)


def _database_exists(settings: MySQLSettings) -> bool:
    connection = connect_mysql(settings, with_database=False)
    try:
        with connection.cursor() as cursor:
            return database_exists(cursor, settings.database)
    finally:
        connection.close()


def _dump_command(settings: MySQLSettings) -> list[str]:
    # MySQL 8.4's mysqldump rejects the mysql-client-only --connect-timeout
    # option. _database_exists() already performs a bounded PyMySQL connection
    # before the dump process is started.
    return [
        "mysqldump",
        f"--host={settings.host}",
        f"--port={settings.port}",
        f"--user={settings.user}",
        "--single-transaction",
        "--routines",
        "--triggers",
        "--events",
        "--no-tablespaces",
        "--set-gtid-purged=OFF",
        settings.database,
    ]


def _write_dump(output: Path, settings: MySQLSettings) -> None:
    environment = os.environ.copy()
    environment["MYSQL_PWD"] = settings.password
    process = subprocess.Popen(
        _dump_command(settings),
        stdout=subprocess.PIPE,
        env=environment,
    )
    assert process.stdout is not None
    try:
        with output.open("xb") as raw_output:
            with gzip.GzipFile(
                fileobj=raw_output, mode="wb", compresslevel=1, mtime=0
            ) as compressed:
                shutil.copyfileobj(process.stdout, compressed)
            raw_output.flush()
            os.fsync(raw_output.fileno())
        return_code = process.wait()
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        process.stdout.close()
    if return_code:
        raise subprocess.CalledProcessError(return_code, process.args)


def backup_database(output: Path, config=None) -> Path:
    settings = settings_from_config(config)
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    partial = output.with_name(f".{output.name}.partial")
    partial.unlink(missing_ok=True)

    try:
        if _database_exists(settings):
            _write_dump(partial, settings)
        else:
            with gzip.GzipFile(
                filename=partial, mode="xb", compresslevel=1, mtime=0
            ) as compressed:
                compressed.write(
                    b"-- NumericalOJ pre-deploy state: configured database did not exist.\n"
                )
        os.replace(partial, output)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
    return output


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        output = backup_database(args.output)
    except Exception as exc:
        print(f"[backup_database] failed: {exc}", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
