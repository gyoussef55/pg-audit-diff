"""Extract schema metadata snapshots from PostgreSQL."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from psycopg import Connection

from pg_audit_diff.migrations_adapters import extract_migrations
from pg_audit_diff.queries_loader import load_query

SNAPSHOT_VERSION = 1

SNAPSHOT_SECTIONS: tuple[str, ...] = (
    "tables",
    "columns",
    "pks",
    "ucs",
    "fks",
    "indexes",
    "constraints",
    "types",
    "extensions",
    "functions",
    "triggers",
    "views",
    "sequences",
    "policies",
    "comments",
)

# Ownership and ACLs legitimately differ between environments (different role names per
# environment), so privileges are only captured when explicitly requested.
OPTIONAL_SECTIONS: tuple[str, ...] = ("privileges",)

# Collation is read from pg_database rather than from current_setting: the lc_collate and
# lc_ctype GUCs were removed in PostgreSQL 17, and the per-database values in pg_database
# are what actually govern text ordering for this schema on every supported version.
SERVER_CONTEXT_QUERY = """
SELECT current_setting('server_version') AS server_version,
       pg_encoding_to_char(d.encoding) AS server_encoding,
       d.datcollate AS lc_collate,
       d.datctype AS lc_ctype
FROM pg_database d
WHERE d.datname = current_database()
"""

USER_SCHEMAS_QUERY = """
SELECT nspname
FROM pg_namespace
WHERE nspname NOT LIKE 'pg\\_%'
  AND nspname <> 'information_schema'
ORDER BY nspname
"""


@dataclass(frozen=True)
class SnapshotOptions:
    """Options controlling schema snapshot extraction."""

    schema: str = "public"
    # Left empty by default so it never silently shadows an explicitly set `schema`;
    # resolve_schemas derives it from `schema` when it is not populated.
    schemas: tuple[str, ...] = ()
    all_schemas: bool = False
    migrations_schema: str = "public"
    # None means "auto-detect only"; a value is an override for a non-standard table name.
    migrations_table: str | None = None
    include_migrations: bool = True
    include_privileges: bool = False
    include_tables: str | None = None
    exclude_tables: str | None = None


def load_snapshot_file(path: Path | str) -> dict[str, Any]:
    """Load and validate snapshot format version from file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Snapshot file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"Cannot read snapshot file {p}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in snapshot file {p}: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in {p}, got {type(data).__name__}")

    if "diff" in data and isinstance(data["diff"], dict) and "tables" not in data:
        raise ValueError(
            f"{p} appears to be a diff report, not a schema snapshot. "
            f"Pass a file written by 'pg-audit-diff snapshot -o'."
        )

    ver = data.get("snapshot_version")
    if ver != SNAPSHOT_VERSION:
        raise ValueError(
            f"Unsupported snapshot_version {ver!r} in {p}; this build reads version "
            f"{SNAPSHOT_VERSION}. Older snapshots record different catalog fields "
            f"and cannot be compared reliably, so re-run 'pg-audit-diff snapshot'."
        )

    return data


def _matches_table_filter(
    table_name: str,
    include_re: re.Pattern[str] | None,
    exclude_re: re.Pattern[str] | None,
) -> bool:
    if include_re and not include_re.search(table_name):
        return False
    return not (exclude_re and exclude_re.search(table_name))


def filter_snapshot_tables(snapshot: dict[str, Any], opts: SnapshotOptions) -> dict[str, Any]:
    """Filter snapshot sections based on include_tables and exclude_tables patterns."""
    if not opts.include_tables and not opts.exclude_tables:
        return snapshot

    inc_re = re.compile(opts.include_tables) if opts.include_tables else None
    exc_re = re.compile(opts.exclude_tables) if opts.exclude_tables else None

    result = dict(snapshot)

    # Tables dict
    if isinstance(result.get("tables"), dict):
        result["tables"] = {
            k: v for k, v in result["tables"].items() if _matches_table_filter(k, inc_re, exc_re)
        }

    # Columns dict of table -> cols
    if isinstance(result.get("columns"), dict):
        result["columns"] = {
            k: v for k, v in result["columns"].items() if _matches_table_filter(k, inc_re, exc_re)
        }

    # Constraints list or dict
    for sec in ("pks", "ucs", "fks", "indexes"):
        val = result.get(sec)
        if isinstance(val, list):
            result[sec] = [
                x
                for x in val
                if _matches_table_filter(str(x.get("table_name", "")), inc_re, exc_re)
            ]
        elif isinstance(val, dict):
            result[sec] = {
                k: v
                for k, v in val.items()
                if _matches_table_filter(str(v.get("table_name", "")), inc_re, exc_re)
            }

    if isinstance(result.get("constraints"), dict):
        result["constraints"] = {
            k: v
            for k, v in result["constraints"].items()
            if _matches_table_filter(k, inc_re, exc_re)
        }

    if isinstance(result.get("triggers"), dict):
        result["triggers"] = {
            k: v
            for k, v in result["triggers"].items()
            if _matches_table_filter(str(v.get("table_name", "")), inc_re, exc_re)
        }

    if isinstance(result.get("policies"), dict):
        result["policies"] = {
            k: v
            for k, v in result["policies"].items()
            if _matches_table_filter(str(v.get("table_name", "")), inc_re, exc_re)
        }

    if isinstance(result.get("sequences"), dict):
        result["sequences"] = {
            k: v
            for k, v in result["sequences"].items()
            if not v.get("owned_by_table")
            or _matches_table_filter(str(v["owned_by_table"]), inc_re, exc_re)
        }

    if isinstance(result.get("comments"), dict):
        result["comments"] = {
            k: v
            for k, v in result["comments"].items()
            if v.get("object_type") not in ("table", "column")
            or _matches_table_filter(str(v.get("object_name", "")), inc_re, exc_re)
        }

    return result


def parse_schema_list(schema: str) -> tuple[str, ...]:
    """Split a comma-separated schema option into individual schema names."""
    parts = tuple(s.strip() for s in (schema or "").split(",") if s.strip())
    return parts or ("public",)


def resolve_schemas(conn: Connection[Any], opts: SnapshotOptions) -> tuple[str, ...]:
    """Determine which schemas to snapshot, expanding --all-schemas against the catalog."""
    if opts.all_schemas:
        rows = conn.execute(USER_SCHEMAS_QUERY).fetchall()
        found = tuple(str(next(iter(row.values()))) for row in rows)
        if found:
            return found
    if opts.schemas:
        return opts.schemas
    return parse_schema_list(opts.schema)


def build_snapshot_params(schemas: tuple[str, ...]) -> dict[str, Any]:
    """Build the bind parameters every catalog query expects.

    Queries reference both %(schema)s and %(schemas)s so they can serve single-schema and
    multi-schema snapshots from one statement; both must always be supplied.
    """
    return {"schema": schemas[0], "schemas": list(schemas)}


def build_schema_snapshot(
    conn: Connection[Any],
    options: SnapshotOptions | None = None,
) -> dict[str, Any]:
    """Extract a JSON-serializable schema snapshot from a database connection."""
    opts = options or SnapshotOptions()

    with conn.transaction():
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;")

        schemas = resolve_schemas(conn, opts)
        params = build_snapshot_params(schemas)

        ctx_row = conn.execute(SERVER_CONTEXT_QUERY).fetchone() or {}
        server_context = {str(k): v for k, v in ctx_row.items()}

        snapshot: dict[str, Any] = {
            "snapshot_version": SNAPSHOT_VERSION,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "server_version": server_context.get("server_version", "unknown"),
            "server_context": server_context,
            "schema": schemas[0],
            "schemas": list(schemas),
        }

        sections = SNAPSHOT_SECTIONS
        if opts.include_privileges:
            if len(schemas) > 1:
                # privileges.sql reads a single schema. Capturing only the first one would
                # silently report "no privilege drift" for every other schema, so refuse
                # rather than return a partial answer.
                raise ValueError(
                    "Privilege capture supports one schema at a time; "
                    f"got {len(schemas)} schemas ({', '.join(schemas)}). "
                    "Run one snapshot per schema, or drop --include-privileges."
                )
            sections = (*sections, *OPTIONAL_SECTIONS)

        for key in sections:
            query = load_query(key)
            row = conn.execute(query, params).fetchone() or {}
            val = next(iter(row.values()), None)
            if val is None:
                val = [] if key in ("pks", "ucs", "fks", "indexes") else {}
            snapshot[key] = val

        snapshot["migrations"] = _snapshot_migrations(conn, opts) if opts.include_migrations else {}

    return filter_snapshot_tables(snapshot, opts)


def _snapshot_migrations(conn: Connection[Any], opts: SnapshotOptions) -> Any:
    """Read the migration history table using framework adapters.

    Adapters probe for table existence with to_regclass, so an absent history table
    returns {} without erroring. Anything else is a real failure and is allowed to
    propagate rather than being reported as an empty history, which would read as
    "both sides agree" and hide drift.
    """
    return extract_migrations(
        conn,
        schema=opts.migrations_schema,
        table_name=opts.migrations_table,
    )
