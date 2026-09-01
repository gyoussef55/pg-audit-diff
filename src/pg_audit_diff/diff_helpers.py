"""Helper utilities for schema difference calculations."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from typing import Any


def normalize_definition(definition: str | None) -> str:
    """Normalize SQL definition string by standardizing whitespace."""
    return " ".join(definition.strip().split()) if definition else ""


def normalize_columns(columns: Any) -> tuple[str, ...]:
    """Normalize column list or comma-separated string to lowercase tuple."""
    if not columns:
        return ()
    if isinstance(columns, str):
        columns = [c.strip() for c in columns.split(",") if c.strip()]
    return tuple(str(col).strip().lower() for col in columns if col is not None)


def normalize_events(events: Any) -> tuple[str, ...]:
    """Normalize trigger event names to sorted uppercase tuple."""
    if not events:
        return ()
    if isinstance(events, str):
        events = [
            e.strip() for e in events.replace(" OR ", ",").replace("/", ",").split(",") if e.strip()
        ]
    return tuple(sorted(str(e).strip().upper() for e in events if e))


def extract_items(data: Any) -> list[dict[str, Any]]:
    """Extract list of object dictionaries from list or dict container."""
    if not data:
        return []
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        items: list[dict[str, Any]] = []
        for key, val in data.items():
            if isinstance(val, dict):
                item_dict = dict(val)
                item_dict.setdefault("name", key)
                items.append(item_dict)
            elif isinstance(val, list):
                for sub in val:
                    if isinstance(sub, dict):
                        item_dict = dict(sub)
                        item_dict.setdefault("table_name", key)
                        items.append(item_dict)
        return items
    return []


def compare_mapped(
    ref_map: dict[str, dict[str, Any]],
    cmp_map: dict[str, dict[str, Any]],
    diff_fn: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any] | None],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Compare two key->object mappings and partition into missing, unexpected, mismatched."""
    missing = {k: ref_map[k] for k in sorted(ref_map.keys() - cmp_map.keys())}
    unexpected = {k: cmp_map[k] for k in sorted(cmp_map.keys() - ref_map.keys())}
    mismatched: dict[str, Any] = {}
    for k in sorted(ref_map.keys() & cmp_map.keys()):
        diff = diff_fn(ref_map[k], cmp_map[k])
        if diff:
            mismatched[k] = diff
    return missing, unexpected, mismatched


def extract_constraints(
    snapshot: dict[str, Any],
    contypes: set[str],
    section_names: tuple[str, ...],
) -> list[dict[str, Any]]:
    """Extract constraint dictionaries matching specific types across snapshot sections."""
    results: list[dict[str, Any]] = []
    for sname in section_names:
        if sname in snapshot:
            results.extend(extract_items(snapshot.get(sname)))
    for c in extract_items(snapshot.get("constraints")):
        ctype = str(c.get("contype") or c.get("constraint_type") or c.get("type") or "").lower()
        if ctype in contypes or (
            not ctype and "c" in contypes and ("definition" in c or "expression" in c)
        ):
            results.append(c)
    return results


def has_attr_diff(ref: dict[str, Any], cmp: dict[str, Any], attrs: tuple[str, ...]) -> bool:
    """Check if any attribute in attrs differs between ref and cmp."""
    return any((a in ref or a in cmp) and ref.get(a) != cmp.get(a) for a in attrs)


def collect_attr_diffs(
    ref: dict[str, Any], cmp: dict[str, Any], attrs: tuple[str, ...]
) -> dict[str, Any]:
    """Return expected/actual pairs for each attribute present on either side that differs."""
    return {
        a: {"expected": ref.get(a), "actual": cmp.get(a)}
        for a in attrs
        if (a in ref or a in cmp) and ref.get(a) != cmp.get(a)
    }


def pair_by_name(
    refs: list[dict[str, Any]],
    cmps: list[dict[str, Any]],
    name_field: str,
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Pair objects that share a logical key, preferring identical names."""
    unmatched_cmps = list(cmps)
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    renamed_refs: list[dict[str, Any]] = []

    for ref in refs:
        ref_name = str(ref.get(name_field) or "").lower()
        match = next(
            (
                i
                for i, cmp in enumerate(unmatched_cmps)
                if str(cmp.get(name_field) or "").lower() == ref_name
            ),
            None,
        )
        if match is None:
            renamed_refs.append(ref)
        else:
            pairs.append((ref, unmatched_cmps.pop(match)))

    unpaired_refs: list[dict[str, Any]] = []
    for ref in renamed_refs:
        if unmatched_cmps:
            pairs.append((ref, unmatched_cmps.pop(0)))
        else:
            unpaired_refs.append(ref)

    return pairs, unpaired_refs, unmatched_cmps


def compare_constraint_attrs(ref: dict[str, Any], cmp: dict[str, Any]) -> bool:
    """Compare constraint validity and deferrability attributes."""
    return not has_attr_diff(
        ref,
        cmp,
        (
            "is_valid",
            "convalidated",
            "is_deferrable",
            "condeferrable",
            "is_deferred",
            "condeferred",
        ),
    )


def compare_table_attrs(r: dict[str, Any], c: dict[str, Any]) -> dict[str, Any] | None:
    """Compare table attributes including type, persistence, storage, and partitioning."""
    diffs: dict[str, Any] = {}
    for attr in (
        "table_type",
        "persistence",
        "tablespace",
        "rls_enabled",
        "rls_forced",
        "is_partitioned",
        "is_partition",
        "parent_table",
        "parent_schema",
    ):
        if (attr in r or attr in c) and r.get(attr) != c.get(attr):
            diffs[attr] = {"expected": r.get(attr), "actual": c.get(attr)}

    r_opts = sorted(str(x) for x in r.get("reloptions") or [])
    c_opts = sorted(str(x) for x in c.get("reloptions") or [])
    if (r.get("reloptions") or c.get("reloptions")) and r_opts != c_opts:
        diffs["reloptions"] = {"expected": r.get("reloptions"), "actual": c.get("reloptions")}

    r_pkey = normalize_definition(r.get("partition_key"))
    c_pkey = normalize_definition(c.get("partition_key"))
    if (r.get("partition_key") or c.get("partition_key")) and r_pkey != c_pkey:
        diffs["partition_key"] = {
            "expected": r.get("partition_key"),
            "actual": c.get("partition_key"),
        }

    r_pbound = normalize_definition(r.get("partition_bound"))
    c_pbound = normalize_definition(c.get("partition_bound"))
    if (r.get("partition_bound") or c.get("partition_bound")) and r_pbound != c_pbound:
        diffs["partition_bound"] = {
            "expected": r.get("partition_bound"),
            "actual": c.get("partition_bound"),
        }

    if not diffs:
        return None
    if set(diffs.keys()) == {"table_type"}:
        return {"expected": r.get("table_type"), "actual": c.get("table_type")}
    return diffs


def _index_structure_key(idx: dict[str, Any]) -> str:
    """Logical index identity without predicate (for definition-change pairing)."""
    tbl = str(idx.get("table_name") or "").lower()
    am = str(idx.get("am_name") or "btree").lower()
    cols = normalize_columns(idx.get("columns"))
    inc = normalize_columns(idx.get("include_columns"))
    uniq = bool(idx.get("is_unique"))
    prim = bool(idx.get("is_primary"))
    return f"{tbl}|{am}|{','.join(cols)}|{','.join(inc)}|{uniq}|{prim}"


def _index_definition_diffs(ref: dict[str, Any], cmp: dict[str, Any]) -> dict[str, Any]:
    """Collect attribute differences for indexes that share the same structure key."""
    attr_diffs = collect_attr_diffs(
        ref,
        cmp,
        ("is_valid", "is_ready", "is_clustered", "tablespace", "persistence"),
    )
    ref_pred = normalize_definition(str(ref.get("predicate") or ""))
    cmp_pred = normalize_definition(str(cmp.get("predicate") or ""))
    if ref_pred != cmp_pred:
        attr_diffs["predicate"] = {"expected": ref.get("predicate"), "actual": cmp.get("predicate")}

    r_opts = sorted(str(x) for x in ref.get("reloptions") or [])
    c_opts = sorted(str(x) for x in cmp.get("reloptions") or [])
    if (ref.get("reloptions") or cmp.get("reloptions")) and r_opts != c_opts:
        attr_diffs["reloptions"] = {
            "expected": ref.get("reloptions"),
            "actual": cmp.get("reloptions"),
        }

    ref_details = normalize_columns(ref.get("column_details"))
    cmp_details = normalize_columns(cmp.get("column_details"))
    if ref_details != cmp_details:
        attr_diffs["column_details"] = {"expected": ref_details, "actual": cmp_details}

    return attr_diffs


def _reconcile_index_definition_changes(
    missing: dict[str, Any],
    unexpected: dict[str, Any],
    mismatched: dict[str, Any],
) -> None:
    """Move predicate/option-only index changes from missing+unexpected into mismatched."""
    if not missing or not unexpected:
        return

    missing_by_struct: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for name, idx in missing.items():
        if isinstance(idx, dict):
            missing_by_struct[_index_structure_key(idx)].append((name, idx))

    unexpected_by_struct: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for name, idx in unexpected.items():
        if isinstance(idx, dict):
            unexpected_by_struct[_index_structure_key(idx)].append((name, idx))

    for struct_key in sorted(set(missing_by_struct) & set(unexpected_by_struct)):
        ref_items = list(missing_by_struct[struct_key])
        cmp_items = list(unexpected_by_struct[struct_key])
        used_cmp: set[str] = set()

        for ref_name, ref_idx in ref_items:
            for cmp_name, cmp_idx in cmp_items:
                if cmp_name in used_cmp:
                    continue
                attr_diffs = _index_definition_diffs(ref_idx, cmp_idx)
                if not attr_diffs:
                    continue
                mismatched[ref_name] = {
                    "expected": ref_idx,
                    "actual": cmp_idx,
                    "diffs": attr_diffs,
                }
                missing.pop(ref_name, None)
                unexpected.pop(cmp_name, None)
                used_cmp.add(cmp_name)
                break


def compare_indexes(ref_indexes: Any, cmp_indexes: Any) -> dict[str, Any]:
    """Compare indexes logically and isolate name_only renames."""

    def _index_key(idx: dict[str, Any]) -> str:
        tbl = str(idx.get("table_name") or "").lower()
        am = str(idx.get("am_name") or "btree").lower()
        cols = normalize_columns(idx.get("columns"))
        inc = normalize_columns(idx.get("include_columns"))
        pred = normalize_definition(str(idx.get("predicate") or ""))
        uniq = bool(idx.get("is_unique"))
        prim = bool(idx.get("is_primary"))
        return f"{tbl}|{am}|{','.join(cols)}|{','.join(inc)}|{pred}|{uniq}|{prim}"

    ref_list = extract_items(ref_indexes)
    cmp_list = extract_items(cmp_indexes)

    ref_by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)
    cmp_by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for idx in ref_list:
        ref_by_key[_index_key(idx)].append(idx)
    for idx in cmp_list:
        cmp_by_key[_index_key(idx)].append(idx)

    ref_duplicates: list[dict[str, Any]] = []
    for _k, items in ref_by_key.items():
        if len(items) > 1:
            ref_duplicates.append(
                {
                    "table_name": items[0].get("table_name"),
                    "columns": items[0].get("columns") or [],
                    "index_names": [str(it.get("index_name") or "") for it in items],
                    "am_name": items[0].get("am_name", "btree"),
                }
            )

    cmp_duplicates: list[dict[str, Any]] = []
    for _k, items in cmp_by_key.items():
        if len(items) > 1:
            cmp_duplicates.append(
                {
                    "table_name": items[0].get("table_name"),
                    "columns": items[0].get("columns") or [],
                    "index_names": [str(it.get("index_name") or "") for it in items],
                    "am_name": items[0].get("am_name", "btree"),
                }
            )

    missing: dict[str, Any] = {}
    unexpected: dict[str, Any] = {}
    mismatched: dict[str, Any] = {}
    name_only: dict[str, Any] = {}

    all_keys = set(ref_by_key.keys()) | set(cmp_by_key.keys())
    for key in sorted(all_keys):
        pairs, unpaired_refs, unpaired_cmps = pair_by_name(
            ref_by_key.get(key, []), cmp_by_key.get(key, []), "index_name"
        )

        for r in unpaired_refs:
            missing[str(r.get("index_name") or key)] = r
        for c in unpaired_cmps:
            unexpected[str(c.get("index_name") or key)] = c

        for r, c in pairs:
            r_name = str(r.get("index_name") or key)
            c_name = str(c.get("index_name") or key)

            attr_diffs = collect_attr_diffs(
                r,
                c,
                ("is_valid", "is_ready", "is_clustered", "tablespace", "persistence"),
            )
            r_opts = sorted(str(x) for x in r.get("reloptions") or [])
            c_opts = sorted(str(x) for x in c.get("reloptions") or [])
            if (r.get("reloptions") or c.get("reloptions")) and r_opts != c_opts:
                attr_diffs["reloptions"] = {
                    "expected": r.get("reloptions"),
                    "actual": c.get("reloptions"),
                }

            ref_details = normalize_columns(r.get("column_details"))
            cmp_details = normalize_columns(c.get("column_details"))
            if ref_details != cmp_details:
                attr_diffs["column_details"] = {"expected": ref_details, "actual": cmp_details}

            if attr_diffs:
                mismatched[r_name] = {"expected": r, "actual": c, "diffs": attr_diffs}
            elif r_name.lower() != c_name.lower():
                name_only[r_name] = {
                    "expected_name": r_name,
                    "actual_name": c_name,
                    "table_name": r.get("table_name"),
                    "columns": r.get("columns"),
                }

    _reconcile_index_definition_changes(missing, unexpected, mismatched)

    return {
        "missing": missing,
        "unexpected": unexpected,
        "mismatched": mismatched,
        "name_only": name_only,
        "duplicates": {
            "reference": ref_duplicates,
            "compared": cmp_duplicates,
        },
    }


def compare_columns(
    ref_schema: dict[str, Any],
    cmp_schema: dict[str, Any],
    *,
    track_ordinal_position: bool = False,
) -> dict[str, Any]:
    """Compare columns across tables including types, precision, nullability, and storage."""
    column_diff: dict[str, Any] = {
        "missing": defaultdict(list),
        "unexpected": defaultdict(list),
        "mismatched": defaultdict(list),
    }

    def _cols_by_table(schema: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        raw = schema.get("columns", {})
        res: dict[str, list[dict[str, Any]]] = {}
        if isinstance(raw, dict):
            for t_name, cols in raw.items():
                res[t_name.lower()] = extract_items(cols)
        elif isinstance(raw, list):
            for c in raw:
                if isinstance(c, dict) and "table_name" in c:
                    res.setdefault(str(c["table_name"]).lower(), []).append(c)

        tables = schema.get("tables", {})
        if isinstance(tables, dict):
            for t_name, t_meta in tables.items():
                t_lower = t_name.lower()
                if t_lower not in res and isinstance(t_meta, dict) and "columns" in t_meta:
                    res[t_lower] = extract_items(t_meta["columns"])
        return res

    ref_cols_by_tbl = _cols_by_table(ref_schema)
    cmp_cols_by_tbl = _cols_by_table(cmp_schema)

    all_tables = set(ref_cols_by_tbl.keys()) | set(cmp_cols_by_tbl.keys())

    for table in sorted(all_tables):
        ref_cols = ref_cols_by_tbl.get(table, [])
        cmp_cols = cmp_cols_by_tbl.get(table, [])

        ref_map = {str(c.get("column_name", "")).lower(): c for c in ref_cols}
        cmp_map = {str(c.get("column_name", "")).lower(): c for c in cmp_cols}

        ref_names = set(ref_map.keys())
        cmp_names = set(cmp_map.keys())

        for col_lower in sorted(ref_names - cmp_names):
            column_diff["missing"][table].append(ref_map[col_lower].get("column_name", col_lower))

        for col_lower in sorted(cmp_names - ref_names):
            column_diff["unexpected"][table].append(
                cmp_map[col_lower].get("column_name", col_lower)
            )

        for col_lower in sorted(ref_names & cmp_names):
            ref_col = ref_map[col_lower]
            cmp_col = cmp_map[col_lower]
            diffs: dict[str, Any] = {}

            # Data type comparison
            ref_type = (
                str(
                    ref_col.get("format_type")
                    or ref_col.get("data_type")
                    or ref_col.get("type")
                    or ""
                )
                .strip()
                .lower()
            )
            cmp_type = (
                str(
                    cmp_col.get("format_type")
                    or cmp_col.get("data_type")
                    or cmp_col.get("type")
                    or ""
                )
                .strip()
                .lower()
            )
            if ref_type != cmp_type:
                diffs["data_type"] = {
                    "expected": ref_col.get("format_type") or ref_col.get("data_type"),
                    "actual": cmp_col.get("format_type") or cmp_col.get("data_type"),
                }

            # Nullability comparison
            ref_null = ref_col.get("is_nullable")
            cmp_null = cmp_col.get("is_nullable")
            if ref_null is not None and cmp_null is not None:
                ref_null_bool = (
                    ref_null if isinstance(ref_null, bool) else str(ref_null).upper() == "YES"
                )
                cmp_null_bool = (
                    cmp_null if isinstance(cmp_null, bool) else str(cmp_null).upper() == "YES"
                )
                if ref_null_bool != cmp_null_bool:
                    diffs["is_nullable"] = {"expected": ref_null, "actual": cmp_null}

            # Storage, default, identity, and generation expressions
            for attr in (
                "column_default",
                "is_identity",
                "identity_generation",
                "is_generated",
                "generation_expression",
                "attstorage",
                "attcompression",
            ):
                if attr in ref_col or attr in cmp_col:
                    r_val = ref_col.get(attr)
                    c_val = cmp_col.get(attr)
                    if r_val != c_val:
                        diffs[attr] = {"expected": r_val, "actual": c_val}

            if track_ordinal_position:
                ref_pos = (
                    ref_col.get("ordinal_position")
                    if "ordinal_position" in ref_col
                    else ref_col.get("attnum")
                )
                cmp_pos = (
                    cmp_col.get("ordinal_position")
                    if "ordinal_position" in cmp_col
                    else cmp_col.get("attnum")
                )
                if ref_pos is not None and cmp_pos is not None and ref_pos != cmp_pos:
                    diffs["ordinal_position"] = {"expected": ref_pos, "actual": cmp_pos}

            if diffs:
                col_display_name = ref_col.get("column_name", col_lower)
                column_diff["mismatched"][table].append({col_display_name: diffs})

    return {
        "missing": dict(column_diff["missing"]),
        "unexpected": dict(column_diff["unexpected"]),
        "mismatched": dict(column_diff["mismatched"]),
    }


def compare_server_context(
    ref_schema: dict[str, Any],
    cmp_schema: dict[str, Any],
) -> dict[str, Any]:
    """Compare server environment context (version, encoding, collations)."""
    diffs: dict[str, Any] = {}
    ref_ctx = ref_schema.get("server_context") or {}
    cmp_ctx = cmp_schema.get("server_context") or {}
    for attr in ("server_version", "server_encoding", "lc_collate", "lc_ctype"):
        r_val = ref_ctx.get(attr) if attr in ref_ctx else ref_schema.get(attr)
        c_val = cmp_ctx.get(attr) if attr in cmp_ctx else cmp_schema.get(attr)
        if r_val is not None and c_val is not None and r_val != c_val:
            diffs[attr] = {"expected": r_val, "actual": c_val}
    return {
        "missing": {},
        "unexpected": {},
        "mismatched": diffs,
    }


__all__ = [
    "compare_columns",
    "compare_constraint_attrs",
    "compare_indexes",
    "compare_mapped",
    "compare_server_context",
    "compare_table_attrs",
    "extract_constraints",
    "extract_items",
    "normalize_columns",
    "normalize_definition",
    "normalize_events",
    "pair_by_name",
]
