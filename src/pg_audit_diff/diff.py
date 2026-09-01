"""Logical comparison of schema snapshots."""

from __future__ import annotations

from typing import Any

from pg_audit_diff.diff_helpers import (
    compare_columns,
    compare_constraint_attrs,
    compare_indexes,
    compare_mapped,
    compare_server_context,
    compare_table_attrs,
    extract_constraints,
    normalize_columns,
    normalize_definition,
)
from pg_audit_diff.diff_objects import (
    compare_comments,
    compare_extensions,
    compare_functions,
    compare_policies,
    compare_sequences,
    compare_triggers,
    compare_types,
    compare_views,
)
from pg_audit_diff.migrations_adapters import compare_migration_records
from pg_audit_diff.privileges import compare_privileges
from pg_audit_diff.schema_identity import (
    compare_schema_sets,
    normalize_pair,
    should_normalize_pair,
)


def _normalize_tables(raw_tables: Any) -> dict[str, dict[str, Any]]:
    """Normalize tables payload into lowercase-keyed dictionary."""
    if isinstance(raw_tables, dict):
        return {k.lower(): v for k, v in raw_tables.items() if isinstance(v, dict)}
    if isinstance(raw_tables, list):
        out: dict[str, dict[str, Any]] = {}
        for item in raw_tables:
            if isinstance(item, dict):
                tbl = item.get("table_name") or item.get("name") or item.get("relname") or ""
                if tbl:
                    out[str(tbl).lower()] = item
        return out
    return {}


def compare_snapshots(
    reference_schema: dict[str, Any],
    compared_schema: dict[str, Any],
    *,
    track_ordinal_position: bool = False,
    extension_version_policy: str = "exact",
    role_mapping: dict[str, str] | None = None,
    migration_framework: str | None = None,
    normalize_schema_names: bool = False,
) -> dict[str, Any]:
    """Compare reference and compared schema snapshots, returning logical drift dictionary."""
    rename_comparison = normalize_schema_names and should_normalize_pair(
        reference_schema, compared_schema
    )
    if rename_comparison:
        schema_diff: dict[str, Any] = {"missing": [], "unexpected": [], "mismatched": {}}
    else:
        schema_diff = compare_schema_sets(reference_schema, compared_schema)

    if normalize_schema_names:
        reference_schema, compared_schema = normalize_pair(reference_schema, compared_schema)

    ref_tables = _normalize_tables(reference_schema.get("tables"))
    cmp_tables = _normalize_tables(compared_schema.get("tables"))

    ref_table_names = set(ref_tables.keys())
    cmp_table_names = set(cmp_tables.keys())

    tbl_m = sorted(ref_table_names - cmp_table_names)
    tbl_u = sorted(cmp_table_names - ref_table_names)
    tbl_d: dict[str, Any] = {}
    for tbl in sorted(ref_table_names & cmp_table_names):
        t_diff = compare_table_attrs(ref_tables[tbl], cmp_tables[tbl])
        if t_diff:
            tbl_d[tbl] = t_diff

    column_diff = compare_columns(
        reference_schema, compared_schema, track_ordinal_position=track_ordinal_position
    )

    ref_pks = {
        str(k.get("table_name") or "").lower(): k
        for k in extract_constraints(
            reference_schema, {"p", "primary_key"}, ("pks", "primary_keys")
        )
    }
    cmp_pks = {
        str(k.get("table_name") or "").lower(): k
        for k in extract_constraints(compared_schema, {"p", "primary_key"}, ("pks", "primary_keys"))
    }
    pk_m, pk_u, pk_d = compare_mapped(
        ref_pks,
        cmp_pks,
        lambda r, c: (
            {"expected": r, "actual": c}
            if normalize_columns(r.get("columns")) != normalize_columns(c.get("columns"))
            or not compare_constraint_attrs(r, c)
            else None
        ),
    )

    def _uc_key(u: dict[str, Any]) -> str:
        tbl = str(u.get("table_name") or "").lower()
        cols = ",".join(normalize_columns(u.get("columns")))
        return f"{tbl}({cols})"

    ref_ucs = {
        _uc_key(u): u
        for u in extract_constraints(
            reference_schema,
            {"u", "unique", "unique_constraint"},
            ("ucs", "unique_constraints"),
        )
    }
    cmp_ucs = {
        _uc_key(u): u
        for u in extract_constraints(
            compared_schema,
            {"u", "unique", "unique_constraint"},
            ("ucs", "unique_constraints"),
        )
    }
    uc_m, uc_u, uc_d = compare_mapped(
        ref_ucs,
        cmp_ucs,
        lambda r, c: {"expected": r, "actual": c} if not compare_constraint_attrs(r, c) else None,
    )

    def _fk_key(f: dict[str, Any]) -> str:
        tbl = str(f.get("table_name") or "").lower()
        cols = ",".join(normalize_columns(f.get("columns")))
        ref_sch = str(f.get("referenced_schema") or f.get("foreign_schema") or "").lower()
        ref_tbl = str(
            f.get("referenced_table") or f.get("foreign_table_name") or f.get("foreign_table") or ""
        ).lower()
        target = f"{ref_sch}.{ref_tbl}" if ref_sch else ref_tbl
        ref_cols = ",".join(
            normalize_columns(
                f.get("referenced_columns")
                or f.get("foreign_columns")
                or f.get("foreign_column_names")
            )
        )
        on_del = str(f.get("on_delete") or f.get("delete_rule") or "").lower()
        on_upd = str(f.get("on_update") or f.get("update_rule") or "").lower()
        if target and (on_del or on_upd):
            return f"{tbl}|{cols}|{target}|{ref_cols}|{on_del}|{on_upd}"
        if target:
            return f"{tbl}|{cols}|{target}|{ref_cols}"
        return f"{tbl}({cols})"

    ref_fks = {
        _fk_key(f): f
        for f in extract_constraints(
            reference_schema, {"f", "foreign_key"}, ("fks", "foreign_keys")
        )
    }
    cmp_fks = {
        _fk_key(f): f
        for f in extract_constraints(compared_schema, {"f", "foreign_key"}, ("fks", "foreign_keys"))
    }
    fk_m, fk_u, fk_d = compare_mapped(
        ref_fks,
        cmp_fks,
        lambda r, c: (
            {"expected": r, "actual": c}
            if not compare_constraint_attrs(r, c) or r.get("match_type") != c.get("match_type")
            else None
        ),
    )

    index_diff = compare_indexes(reference_schema.get("indexes"), compared_schema.get("indexes"))

    def _check_key(c: dict[str, Any]) -> str:
        tbl = str(c.get("table_name") or "").lower()
        norm_def = normalize_definition(str(c.get("definition") or c.get("expression") or ""))
        return f"{tbl}|{norm_def}"

    def _constraint_diff(r: dict[str, Any], c: dict[str, Any]) -> dict[str, Any] | None:
        return {"expected": r, "actual": c} if not compare_constraint_attrs(r, c) else None

    ref_chk = {
        _check_key(c): c
        for c in extract_constraints(reference_schema, {"c", "check"}, ("check_constraints",))
    }
    cmp_chk = {
        _check_key(c): c
        for c in extract_constraints(compared_schema, {"c", "check"}, ("check_constraints",))
    }
    chk_m, chk_u, chk_d = compare_mapped(ref_chk, cmp_chk, _constraint_diff)

    excl_types = {"x", "exclusion", "exclude"}
    ref_excl = {
        _check_key(c): c
        for c in extract_constraints(reference_schema, excl_types, ("exclusion_constraints",))
    }
    cmp_excl = {
        _check_key(c): c
        for c in extract_constraints(compared_schema, excl_types, ("exclusion_constraints",))
    }
    excl_m, excl_u, excl_d = compare_mapped(ref_excl, cmp_excl, _constraint_diff)

    type_diff = compare_types(reference_schema.get("types"), compared_schema.get("types"))
    func_diff = compare_functions(
        reference_schema.get("functions"), compared_schema.get("functions")
    )
    trg_diff = compare_triggers(reference_schema.get("triggers"), compared_schema.get("triggers"))
    view_diff = compare_views(reference_schema.get("views"), compared_schema.get("views"))
    seq_diff = compare_sequences(
        reference_schema.get("sequences"), compared_schema.get("sequences")
    )
    pol_diff = compare_policies(reference_schema.get("policies"), compared_schema.get("policies"))
    ext_diff = compare_extensions(
        reference_schema.get("extensions"),
        compared_schema.get("extensions"),
        version_policy=extension_version_policy,
    )

    mig_diff = compare_migration_records(
        reference_schema.get("migrations"),
        compared_schema.get("migrations"),
        framework=migration_framework,
    )
    priv_diff = compare_privileges(
        reference_schema.get("privileges"),
        compared_schema.get("privileges"),
        role_mapping=role_mapping,
    )
    comments_diff = compare_comments(
        reference_schema.get("comments"),
        compared_schema.get("comments"),
    )
    server_ctx_diff = compare_server_context(reference_schema, compared_schema)

    return {
        "schemas": schema_diff,
        "tables": {"missing": tbl_m, "unexpected": tbl_u, "mismatched": tbl_d},
        "columns": column_diff,
        "primary_keys": {"missing": pk_m, "unexpected": pk_u, "mismatched": pk_d},
        "unique_constraints": {
            "missing": uc_m,
            "unexpected": uc_u,
            "mismatched": uc_d,
        },
        "foreign_keys": {"missing": fk_m, "unexpected": fk_u, "mismatched": fk_d},
        "indexes": index_diff,
        "check_constraints": {
            "missing": chk_m,
            "unexpected": chk_u,
            "mismatched": chk_d,
        },
        "exclusion_constraints": {
            "missing": excl_m,
            "unexpected": excl_u,
            "mismatched": excl_d,
        },
        "types": type_diff,
        "views": view_diff,
        "sequences": seq_diff,
        "policies": pol_diff,
        "functions": func_diff,
        "triggers": trg_diff,
        "extensions": ext_diff,
        "comments": comments_diff,
        "migrations": mig_diff,
        "privileges": priv_diff,
        "server_context": server_ctx_diff,
    }


DRIFT_BUCKETS: tuple[str, ...] = ("missing", "unexpected", "mismatched")


def has_drift(
    diff: dict[str, Any],
    *,
    include_renames: bool = False,
    include_server_context: bool = False,
) -> bool:
    """Return True if any section has missing, unexpected, or mismatched items."""
    buckets = (*DRIFT_BUCKETS, "name_only") if include_renames else DRIFT_BUCKETS
    for sec_name, sec_data in diff.items():
        if sec_name == "server_context" and not include_server_context:
            continue
        if not isinstance(sec_data, dict):
            continue
        if any(sec_data.get(bucket) for bucket in buckets):
            return True
    return False
