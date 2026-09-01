"""Pluggable migration history adapters for PostgreSQL schema drift detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from psycopg import Connection

from pg_audit_diff.queries_loader import validate_sql_identifier


@dataclass(frozen=True)
class FrameworkSpec:
    """Specification for a database migration framework adapter."""

    name: str
    default_table: str
    query_template: str
    key_field: str
    checksum_fields: tuple[str, ...]
    failure_field: str | None = None
    failure_expected_value: Any = None


FRAMEWORK_SPECS: dict[str, FrameworkSpec] = {
    "typeorm": FrameworkSpec(
        name="typeorm",
        default_table="migrations",
        query_template="""
            SELECT COALESCE(
                json_agg(
                    json_build_object(
                        'id', id,
                        'timestamp', timestamp,
                        'name', name
                    ) ORDER BY id
                ),
                '[]'::json
            )
            FROM {schema}.{table}
        """,
        key_field="name",
        checksum_fields=("timestamp", "checksum", "hash"),
    ),
    "flyway": FrameworkSpec(
        name="flyway",
        default_table="flyway_schema_history",
        query_template="""
            SELECT COALESCE(
                json_agg(
                    json_build_object(
                        'installed_rank', installed_rank,
                        'version', version,
                        'description', description,
                        'type', type,
                        'script', script,
                        'checksum', checksum,
                        'installed_by', installed_by,
                        'installed_on', installed_on::text,
                        'execution_time', execution_time,
                        'success', success
                    ) ORDER BY installed_rank
                ),
                '[]'::json
            )
            FROM {schema}.{table}
        """,
        key_field="version",
        checksum_fields=("checksum", "script", "type"),
        failure_field="success",
        failure_expected_value=True,
    ),
    "alembic": FrameworkSpec(
        name="alembic",
        default_table="alembic_version",
        query_template="""
            SELECT COALESCE(
                json_agg(
                    json_build_object(
                        'version_num', version_num
                    )
                ),
                '[]'::json
            )
            FROM {schema}.{table}
        """,
        key_field="version_num",
        checksum_fields=(),
    ),
    "liquibase": FrameworkSpec(
        name="liquibase",
        default_table="databasechangelog",
        query_template="""
            SELECT COALESCE(
                json_agg(
                    json_build_object(
                        'id', id,
                        'author', author,
                        'filename', filename,
                        'dateexecuted', dateexecuted::text,
                        'orderexecuted', orderexecuted,
                        'exectype', exectype,
                        'md5sum', md5sum,
                        'description', description,
                        'comments', comments,
                        'tag', tag,
                        'liquibase', liquibase
                    ) ORDER BY orderexecuted
                ),
                '[]'::json
            )
            FROM {schema}.{table}
        """,
        key_field="id",
        checksum_fields=("md5sum", "filename", "author"),
        failure_field="exectype",
        failure_expected_value="EXECUTED",
    ),
    "golang-migrate": FrameworkSpec(
        name="golang-migrate",
        default_table="schema_migrations",
        query_template="""
            SELECT COALESCE(
                json_agg(
                    json_build_object(
                        'version', version,
                        'dirty', dirty
                    ) ORDER BY version
                ),
                '[]'::json
            )
            FROM {schema}.{table}
        """,
        key_field="version",
        checksum_fields=(),
        failure_field="dirty",
        failure_expected_value=False,
    ),
    "django": FrameworkSpec(
        name="django",
        default_table="django_migrations",
        query_template="""
            SELECT COALESCE(
                json_agg(
                    json_build_object(
                        'id', id,
                        'app', app,
                        'name', name,
                        'applied', applied::text
                    ) ORDER BY id
                ),
                '[]'::json
            )
            FROM {schema}.{table}
        """,
        key_field="name",
        checksum_fields=("app",),
    ),
    "rails": FrameworkSpec(
        name="rails",
        default_table="schema_migrations",
        query_template="""
            SELECT COALESCE(
                json_agg(
                    json_build_object(
                        'version', version
                    ) ORDER BY version
                ),
                '[]'::json
            )
            FROM {schema}.{table}
        """,
        key_field="version",
        checksum_fields=(),
    ),
}


def _table_exists(conn: Connection[Any], schema: str, table: str) -> bool:
    qualified = f"{schema}.{table}"
    probe = conn.execute("SELECT to_regclass(%s) IS NOT NULL AS present", (qualified,)).fetchone()
    return bool(probe and next(iter(probe.values()), False))


def _has_dirty_column(conn: Connection[Any], schema: str, table: str) -> bool:
    query = """
        SELECT EXISTS (
            SELECT 1 FROM pg_attribute a
            JOIN pg_class c ON a.attrelid = c.oid
            JOIN pg_namespace n ON c.relnamespace = n.oid
            WHERE n.nspname = %s AND c.relname = %s
              AND a.attname = 'dirty' AND NOT a.attisdropped
        ) AS has_dirty
    """
    row = conn.execute(query, (schema, table)).fetchone()
    return bool(row and next(iter(row.values()), False))


def detect_framework_from_db(conn: Connection[Any], schema: str) -> tuple[str, str] | None:
    """Auto-detect migration framework and table from PostgreSQL catalog."""
    # Specific tables first
    if _table_exists(conn, schema, "flyway_schema_history"):
        return "flyway", "flyway_schema_history"
    if _table_exists(conn, schema, "alembic_version"):
        return "alembic", "alembic_version"
    if _table_exists(conn, schema, "databasechangelog"):
        return "liquibase", "databasechangelog"
    if _table_exists(conn, schema, "django_migrations"):
        return "django", "django_migrations"
    if _table_exists(conn, schema, "schema_migrations"):
        if _has_dirty_column(conn, schema, "schema_migrations"):
            return "golang-migrate", "schema_migrations"
        return "rails", "schema_migrations"
    if _table_exists(conn, schema, "migrations"):
        return "typeorm", "migrations"
    return None


def detect_framework_from_data(data: Any) -> str:
    """Infer framework name from snapshot data."""
    if isinstance(data, dict) and data.get("framework"):
        return str(data["framework"]).lower()

    records = _extract_records_list(data)
    if not records:
        return "generic"

    first = records[0]
    if "installed_rank" in first or "success" in first:
        return "flyway"
    if "dirty" in first:
        return "golang-migrate"
    if "version_num" in first:
        return "alembic"
    if "md5sum" in first or "orderexecuted" in first or "exectype" in first:
        return "liquibase"
    if "app" in first and "applied" in first:
        return "django"
    if "timestamp" in first and "name" in first:
        return "typeorm"
    if "version" in first and len(first) <= 2:
        return "rails"
    return "generic"


def extract_migrations(
    conn: Connection[Any],
    schema: str,
    framework: str | None = None,
    table_name: str | None = None,
) -> dict[str, Any]:
    """Extract migrations metadata snapshot from database connection."""
    schema_clean = validate_sql_identifier(schema, "schema")
    fw_choice = (framework or "auto").lower()

    target_fw: str | None = None
    target_tbl: str | None = None

    if fw_choice != "auto":
        target_fw = fw_choice
        target_tbl = table_name or (
            FRAMEWORK_SPECS[target_fw].default_table
            if target_fw in FRAMEWORK_SPECS
            else "migrations"
        )
    else:
        detected = detect_framework_from_db(conn, schema_clean)
        if detected:
            target_fw, target_tbl = detected
        elif table_name and _table_exists(conn, schema_clean, table_name):
            target_fw = "typeorm"
            target_tbl = table_name
        else:
            return {}

    table_clean = validate_sql_identifier(target_tbl, "table")
    spec = FRAMEWORK_SPECS.get(target_fw)

    if not _table_exists(conn, schema_clean, table_clean):
        return {}

    if spec:
        query = spec.query_template.format(schema=schema_clean, table=table_clean)
    else:
        query = f"SELECT COALESCE(json_agg(t), '[]'::json) FROM {schema_clean}.{table_clean} t"

    row = conn.execute(query).fetchone() or {}
    records: Any = next(iter(row.values()), []) or []
    if isinstance(records, dict):
        records = [records]

    return {
        "framework": target_fw,
        "table": table_clean,
        "records": records,
    }


def _extract_records_list(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        if "records" in data and isinstance(data["records"], list):
            return [r for r in data["records"] if isinstance(r, dict)]
        # Map of key -> dict
        items: list[dict[str, Any]] = []
        for k, v in data.items():
            if k in ("framework", "table", "schema"):
                continue
            if isinstance(v, dict):
                d = dict(v)
                d.setdefault("name", k)
                items.append(d)
        return items
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    return []


def _record_key(rec: dict[str, Any], fw: str) -> str:
    if fw == "flyway":
        v = rec.get("version")
        if v is not None and str(v).strip():
            return str(v).strip()
        return str(rec.get("script") or rec.get("installed_rank") or rec.get("description") or "")
    if fw == "alembic":
        return str(rec.get("version_num") or "")
    if fw == "django":
        app = rec.get("app")
        name = rec.get("name")
        return f"{app}.{name}" if app and name else str(name or rec.get("id") or "")
    if fw == "liquibase":
        return str(rec.get("id") or "")
    if fw in ("golang-migrate", "rails"):
        return str(rec.get("version") or "")
    return str(rec.get("name") or rec.get("id") or rec.get("version") or "")


def _check_failure_state(rec: dict[str, Any], fw: str) -> tuple[bool, dict[str, Any] | None]:
    if fw == "flyway":
        suc = rec.get("success")
        if suc is False or str(suc).lower() == "false":
            return True, {"success": {"expected": True, "actual": False}}
    elif fw == "golang-migrate":
        dirty = rec.get("dirty")
        if dirty is True or str(dirty).lower() in ("true", "1"):
            return True, {"dirty": {"expected": False, "actual": True}}
    elif fw == "liquibase":
        exectype = str(rec.get("exectype", "")).upper()
        if exectype and exectype not in ("EXECUTED", "MARK_RAN"):
            return True, {"exectype": {"expected": "EXECUTED", "actual": exectype}}
    return False, None


def compare_migration_records(
    ref_migs: Any,
    cmp_migs: Any,
    *,
    framework: str | None = None,
) -> dict[str, Any]:
    """Compare migration history between reference and compared schema snapshots."""
    ref_records = _extract_records_list(ref_migs)
    cmp_records = _extract_records_list(cmp_migs)

    fw = (
        framework
        or (
            ref_migs.get("framework")
            if isinstance(ref_migs, dict) and ref_migs.get("framework")
            else None
        )
        or detect_framework_from_data(ref_records or cmp_records)
    )

    ref_map: dict[str, dict[str, Any]] = {}
    ref_order: list[str] = []
    for r in ref_records:
        k = _record_key(r, fw)
        if k:
            ref_map[k] = r
            ref_order.append(k)

    cmp_map: dict[str, dict[str, Any]] = {}
    cmp_order: list[str] = []
    for c in cmp_records:
        k = _record_key(c, fw)
        if k:
            cmp_map[k] = c
            cmp_order.append(k)

    missing = {k: ref_map[k] for k in sorted(ref_map.keys() - cmp_map.keys())}
    unexpected = {k: cmp_map[k] for k in sorted(cmp_map.keys() - ref_map.keys())}
    mismatched: dict[str, Any] = {}

    # Check shared keys
    spec = FRAMEWORK_SPECS.get(fw)
    chk_fields = spec.checksum_fields if spec else ("checksum", "hash", "timestamp")

    common_keys = sorted(ref_map.keys() & cmp_map.keys())
    for k in common_keys:
        r = ref_map[k]
        c = cmp_map[k]
        diffs: dict[str, Any] = {}

        # 1. Attribute & checksum mismatches
        for attr in chk_fields:
            if (attr in r or attr in c) and r.get(attr) != c.get(attr):
                diffs[attr] = {"expected": r.get(attr), "actual": c.get(attr)}

        for extra in (
            "installed_rank",
            "type",
            "description",
            "execution_time",
            "author",
            "filename",
        ):
            if (attr := extra) in r and attr in c and r.get(attr) != c.get(attr):
                diffs[attr] = {"expected": r.get(attr), "actual": c.get(attr)}

        # 2. Failure state detection
        is_fail_r, _fail_diff_r = _check_failure_state(r, fw)
        is_fail_c, fail_diff_c = _check_failure_state(c, fw)
        if is_fail_c and fail_diff_c:
            diffs.update(fail_diff_c)
        elif is_fail_r != is_fail_c:
            diffs["failure_state"] = {"expected": not is_fail_r, "actual": not is_fail_c}

        if diffs:
            res = dict(diffs)
            res["expected"] = r
            res["actual"] = c
            mismatched[k] = res

    # 3. Detect out-of-order execution among common migrations
    ref_common_seq = [k for k in ref_order if k in cmp_map]
    cmp_common_seq = [k for k in cmp_order if k in ref_map]
    if ref_common_seq != cmp_common_seq:
        for idx, k in enumerate(cmp_common_seq):
            if idx < len(ref_common_seq) and ref_common_seq[idx] != k:
                expected_idx = ref_common_seq.index(k)
                if k not in mismatched:
                    mismatched[k] = {"expected": ref_map[k], "actual": cmp_map[k]}
                mismatched[k]["out_of_order"] = {
                    "expected_position": expected_idx,
                    "actual_position": idx,
                }

    # 4. Check for failure states in unexpected/missing migrations
    for k, c in unexpected.items():
        is_fail, fail_diff = _check_failure_state(c, fw)
        if is_fail and fail_diff:
            if k not in mismatched:
                mismatched[k] = {"expected": None, "actual": c}
            mismatched[k].update(fail_diff)

    return {"missing": missing, "unexpected": unexpected, "mismatched": mismatched}
