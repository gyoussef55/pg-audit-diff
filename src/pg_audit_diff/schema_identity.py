"""Neutralize a snapshot's own schema name so cross-schema comparison is meaningful.

PostgreSQL renders many catalog values as fully schema-qualified text: format_type
returns `myschema.user_role`, column defaults contain `nextval('myschema.t_id_seq')`,
pg_get_viewdef and pg_get_functiondef embed the schema throughout the body, and foreign
keys record the referenced schema.

Rewriting each snapshot's own schema name to a shared placeholder makes the comparison
schema-relative. Used only when ``compare_snapshots(..., normalize_schema_names=True)``.
"""

from __future__ import annotations

import re
from typing import Any

SCHEMA_PLACEHOLDER = "@schema"

# Fields whose whole value is a schema name. Everywhere else a schema name is only
# recognized when it qualifies an identifier, so a table that happens to share the
# schema's name is left alone.
SCHEMA_NAME_FIELDS = frozenset(
    {
        "schema_name",
        "schema",
        "table_schema",
        "referenced_schema",
        "foreign_schema",
        "parent_schema",
        "namespace",
        "extension_schema",
    }
)


def snapshot_schemas(snapshot: dict[str, Any]) -> tuple[str, ...]:
    """Return the schema names a snapshot was taken from."""
    listed = snapshot.get("schemas")
    if isinstance(listed, (list, tuple)) and listed:
        return tuple(str(s) for s in listed if s)
    single = snapshot.get("schema")
    return (str(single),) if single else ()


def compare_schema_sets(
    reference: dict[str, Any],
    compared: dict[str, Any],
) -> dict[str, Any]:
    """Report schema names present on one side but not the other."""
    ref = set(snapshot_schemas(reference))
    cmp = set(snapshot_schemas(compared))
    return {
        "missing": sorted(ref - cmp),
        "unexpected": sorted(cmp - ref),
        "mismatched": {},
    }


def should_normalize_pair(
    reference: dict[str, Any],
    compared: dict[str, Any],
) -> bool:
    """Whether a pair qualifies for schema-name rewriting (single-schema rename only)."""
    ref_schemas = set(snapshot_schemas(reference))
    cmp_schemas = set(snapshot_schemas(compared))
    if ref_schemas == cmp_schemas:
        return False
    return len(ref_schemas) == 1 and len(cmp_schemas) == 1


def _build_pattern(schemas: tuple[str, ...]) -> re.Pattern[str] | None:
    """Match a schema name only where it qualifies an identifier, bare or quoted."""
    if not schemas:
        return None
    alternatives = "|".join(re.escape(s) for s in sorted(schemas, key=len, reverse=True))
    return re.compile(rf'(?<![\w$."])"?({alternatives})"?(?=\.)')


def _rewrite(
    value: Any,
    pattern: re.Pattern[str],
    schemas: frozenset[str],
    *,
    field: str | None = None,
) -> Any:
    if isinstance(value, str):
        if field in SCHEMA_NAME_FIELDS and value in schemas:
            return SCHEMA_PLACEHOLDER
        return pattern.sub(SCHEMA_PLACEHOLDER, value)
    if isinstance(value, dict):
        return {
            (pattern.sub(SCHEMA_PLACEHOLDER, k) if isinstance(k, str) else k): _rewrite(
                v, pattern, schemas, field=k if isinstance(k, str) else None
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_rewrite(v, pattern, schemas, field=field) for v in value]
    return value


def normalize_schema_identity(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Replace a snapshot's own schema names with a placeholder, everywhere they appear."""
    schemas = snapshot_schemas(snapshot)
    pattern = _build_pattern(schemas)
    if pattern is None:
        return snapshot

    schema_set = frozenset(schemas)
    normalized: dict[str, Any] = {}
    for key, value in snapshot.items():
        if key in ("schema", "schemas", "snapshot_version", "captured_at", "server_version"):
            normalized[key] = value
            continue
        normalized[key] = _rewrite(value, pattern, schema_set)
    return normalized


def normalize_pair(
    reference: dict[str, Any],
    compared: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Normalize both snapshots for a single-schema rename, otherwise return unchanged."""
    if not should_normalize_pair(reference, compared):
        return reference, compared
    return normalize_schema_identity(reference), normalize_schema_identity(compared)
