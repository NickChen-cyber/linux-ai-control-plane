from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Callable


MIGRATIONS_PATH = Path(__file__).resolve().parents[1] / "migrations"


def apply_migrations(connect: Callable[[], Any]) -> list[str]:
    """Apply immutable SQL migrations once and verify their checksums thereafter."""
    applied_now: list[str] = []
    with connect() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS schema_migrations (
                   version TEXT PRIMARY KEY,
                   filename TEXT NOT NULL,
                   checksum_sha256 TEXT NOT NULL,
                   applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
               )"""
        )
        baseline = MIGRATIONS_PATH / "001_init.sql"
        if baseline.exists():
            baseline_checksum = hashlib.sha256(baseline.read_bytes()).hexdigest()
            core_exists = connection.execute("SELECT to_regclass('public.platform_users') AS name").fetchone()["name"]
            if core_exists:
                connection.execute(
                    """INSERT INTO schema_migrations(version,filename,checksum_sha256)
                       VALUES ('001','001_init.sql',%s) ON CONFLICT(version) DO NOTHING""",
                    (baseline_checksum,),
                )
        known = {
            row["version"]: row["checksum_sha256"]
            for row in connection.execute("SELECT version,checksum_sha256 FROM schema_migrations").fetchall()
        }
        for path in sorted(MIGRATIONS_PATH.glob("[0-9][0-9][0-9]_*.sql")):
            version = path.name.split("_", 1)[0]
            sql = path.read_text(encoding="utf-8")
            checksum = hashlib.sha256(sql.encode("utf-8")).hexdigest()
            if version in known:
                if known[version] != checksum:
                    raise RuntimeError(f"資料庫 migration {version} checksum 不一致；禁止修改已套用 migration")
                continue
            connection.execute(sql)
            connection.execute(
                "INSERT INTO schema_migrations(version,filename,checksum_sha256) VALUES (%s,%s,%s)",
                (version, path.name, checksum),
            )
            applied_now.append(version)
    return applied_now


def migration_status(connect: Callable[[], Any]) -> dict[str, Any]:
    files = sorted(MIGRATIONS_PATH.glob("[0-9][0-9][0-9]_*.sql"))
    with connect() as connection:
        rows = connection.execute(
            "SELECT version,filename,checksum_sha256,applied_at FROM schema_migrations ORDER BY version"
        ).fetchall()
    applied = {row["version"]: row for row in rows}
    return {
        "currentVersion": rows[-1]["version"] if rows else None,
        "latestVersion": files[-1].name.split("_", 1)[0] if files else None,
        "pending": [path.name for path in files if path.name.split("_", 1)[0] not in applied],
        "history": [
            {"version": row["version"], "filename": row["filename"],
             "checksumSha256": row["checksum_sha256"], "appliedAt": row["applied_at"].isoformat()}
            for row in rows
        ],
    }
