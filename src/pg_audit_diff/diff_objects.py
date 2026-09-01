"""Object-specific difference calculation routines."""

from __future__ import annotations

import re
from typing import Any

from pg_audit_diff.diff_helpers import (
    compare_mapped,
    extract_items,
    normalize_definition,
    normalize_events,
)


def compare_enums(ref_type: dict[str, Any], cmp_type: dict[str, Any]) -> dict[str, Any] | None:
    ref_vals = [str(x) for x in ref_type.get("enum_values", [])]
    cmp_vals = [str(x) for x in cmp_type.get("enum_values", [])]
    if ref_vals != cmp_vals:
        return {
            "expected": ref_vals,
            "actual": cmp_vals,
            "order_only": sorted(ref_vals) == sorted(cmp_vals),
        }
    return None


def compare_domains(ref_type: dict[str, Any], cmp_type: dict[str, Any]) -> dict[str, Any] | None:
    diffs: dict[str, Any] = {}
    for attr in ("base_type", "is_nullable", "domain_default", "constraints"):
        if ref_type.get(attr) != cmp_type.get(attr):
            diffs[attr] = {"expected": ref_type.get(attr), "actual": cmp_type.get(attr)}
    return diffs or None


def compare_composite_types(
    ref_type: dict[str, Any], cmp_type: dict[str, Any]
) -> dict[str, Any] | None:
    ref_attrs = ref_type.get("attributes", [])
    cmp_attrs = cmp_type.get("attributes", [])
    if ref_attrs != cmp_attrs:
        return {"expected": ref_attrs, "actual": cmp_attrs}
    return None


def compare_types(ref_types: Any, cmp_types: Any) -> dict[str, Any]:
    ref_list = extract_items(ref_types)
    cmp_list = extract_items(cmp_types)
    ref_map = {str(t.get("type_name") or t.get("name") or "").lower(): t for t in ref_list}
    cmp_map = {str(t.get("type_name") or t.get("name") or "").lower(): t for t in cmp_list}

    def _type_diff(r: dict[str, Any], c: dict[str, Any]) -> dict[str, Any] | None:
        r_kind = str(r.get("type_kind") or r.get("kind") or "").lower()
        c_kind = str(c.get("type_kind") or c.get("kind") or "").lower()
        if r_kind != c_kind:
            return {"type_kind": {"expected": r_kind, "actual": c_kind}}
        if r_kind == "enum":
            return compare_enums(r, c)
        if r_kind == "domain":
            return compare_domains(r, c)
        if r_kind == "composite":
            return compare_composite_types(r, c)
        return None

    missing, unexpected, mismatched = compare_mapped(ref_map, cmp_map, _type_diff)
    return {"missing": missing, "unexpected": unexpected, "mismatched": mismatched}


def compare_functions(ref_funcs: Any, cmp_funcs: Any) -> dict[str, Any]:
    ref_list = extract_items(ref_funcs)
    cmp_list = extract_items(cmp_funcs)

    def _func_key(f: dict[str, Any]) -> str:
        sch = f.get("schema_name", "public")
        fn = f.get("function_name", "")
        sig = f.get("function_signature", "")
        return str(f.get("function_key") or f.get("identity") or f"{sch}.{fn}({sig})").lower()

    ref_map = {_func_key(f): f for f in ref_list}
    cmp_map = {_func_key(f): f for f in cmp_list}

    def _func_diff(r: dict[str, Any], c: dict[str, Any]) -> dict[str, Any] | None:
        diffs: dict[str, Any] = {}
        for attr in (
            "return_type",
            "prokind",
            "volatility",
            "is_security_definer",
            "is_leakproof",
            "parallel_safety",
            "config",
        ):
            if (attr in r or attr in c) and r.get(attr) != c.get(attr):
                diffs[attr] = {"expected": r.get(attr), "actual": c.get(attr)}

        r_def = normalize_definition(str(r.get("definition") or r.get("src") or ""))
        c_def = normalize_definition(str(c.get("definition") or c.get("src") or ""))
        if r_def != c_def:
            diffs["definition"] = {"expected": r.get("definition"), "actual": c.get("definition")}

        if diffs:
            res: dict[str, Any] = dict(diffs)
            res["expected"] = r
            res["actual"] = c
            return res
        return None

    missing, unexpected, mismatched = compare_mapped(ref_map, cmp_map, _func_diff)
    return {"missing": missing, "unexpected": unexpected, "mismatched": mismatched}


def compare_triggers(ref_trgs: Any, cmp_trgs: Any) -> dict[str, Any]:
    ref_list = extract_items(ref_trgs)
    cmp_list = extract_items(cmp_trgs)

    def _trg_key(t: dict[str, Any]) -> str:
        sch = t.get("schema_name", "public")
        tbl = t.get("table_name", "")
        trg = t.get("trigger_name", "")
        return str(t.get("trigger_key") or f"{sch}.{tbl}.{trg}").lower()

    ref_map = {_trg_key(t): t for t in ref_list}
    cmp_map = {_trg_key(t): t for t in cmp_list}

    def _trg_diff(r: dict[str, Any], c: dict[str, Any]) -> dict[str, Any] | None:
        diffs: dict[str, Any] = {}
        if normalize_events(r.get("events") or r.get("event_manipulation")) != normalize_events(
            c.get("events") or c.get("event_manipulation")
        ):
            diffs["events"] = {"expected": r.get("events"), "actual": c.get("events")}

        for attr in ("action_timing", "orientation"):
            if (attr in r or attr in c) and r.get(attr) != c.get(attr):
                diffs[attr] = {"expected": r.get(attr), "actual": c.get(attr)}

        r_enabled = r.get("is_enabled", True)
        c_enabled = c.get("is_enabled", True)
        if r_enabled != c_enabled:
            diffs["enabled"] = {"expected": r_enabled, "actual": c_enabled}

        r_stmt = normalize_definition(str(r.get("action_statement") or ""))
        c_stmt = normalize_definition(str(c.get("action_statement") or ""))
        if r_stmt != c_stmt:
            diffs["action_statement"] = {
                "expected": r.get("action_statement"),
                "actual": c.get("action_statement"),
            }

        if diffs:
            res: dict[str, Any] = dict(diffs)
            res["expected"] = r
            res["actual"] = c
            return res
        return None

    missing, unexpected, mismatched = compare_mapped(ref_map, cmp_map, _trg_diff)
    return {"missing": missing, "unexpected": unexpected, "mismatched": mismatched}


def compare_views(ref_views: Any, cmp_views: Any) -> dict[str, Any]:
    ref_list = extract_items(ref_views)
    cmp_list = extract_items(cmp_views)
    ref_map = {
        str(v.get("view_name") or v.get("table_name") or v.get("name") or "").lower(): v
        for v in ref_list
    }
    cmp_map = {
        str(v.get("view_name") or v.get("table_name") or v.get("name") or "").lower(): v
        for v in cmp_list
    }

    def _view_diff(r: dict[str, Any], c: dict[str, Any]) -> dict[str, Any] | None:
        diffs: dict[str, Any] = {}
        for attr in ("view_type", "is_populated"):
            if (attr in r or attr in c) and r.get(attr) != c.get(attr):
                diffs[attr] = {"expected": r.get(attr), "actual": c.get(attr)}

        r_def = normalize_definition(str(r.get("definition") or ""))
        c_def = normalize_definition(str(c.get("definition") or ""))
        if r_def != c_def:
            diffs["definition"] = {
                "expected": r.get("definition"),
                "actual": c.get("definition"),
            }
        if diffs:
            res: dict[str, Any] = dict(diffs)
            res["expected"] = r
            res["actual"] = c
            return res
        return None

    missing, unexpected, mismatched = compare_mapped(ref_map, cmp_map, _view_diff)
    return {"missing": missing, "unexpected": unexpected, "mismatched": mismatched}


def compare_sequences(ref_seqs: Any, cmp_seqs: Any) -> dict[str, Any]:
    ref_list = extract_items(ref_seqs)
    cmp_list = extract_items(cmp_seqs)
    ref_map = {str(s.get("sequence_name") or s.get("name") or "").lower(): s for s in ref_list}
    cmp_map = {str(s.get("sequence_name") or s.get("name") or "").lower(): s for s in cmp_list}

    def _seq_diff(r: dict[str, Any], c: dict[str, Any]) -> dict[str, Any] | None:
        diffs: dict[str, Any] = {}
        for attr in (
            "data_type",
            "start_value",
            "min_value",
            "max_value",
            "increment_by",
            "cycle",
            "cache_size",
            "owned_by_table",
            "owned_by_column",
        ):
            if (attr in r or attr in c) and r.get(attr) != c.get(attr):
                diffs[attr] = {"expected": r.get(attr), "actual": c.get(attr)}
        if diffs:
            res: dict[str, Any] = dict(diffs)
            res["expected"] = r
            res["actual"] = c
            return res
        return None

    missing, unexpected, mismatched = compare_mapped(ref_map, cmp_map, _seq_diff)
    return {"missing": missing, "unexpected": unexpected, "mismatched": mismatched}


def compare_policies(ref_pols: Any, cmp_pols: Any) -> dict[str, Any]:
    ref_list = extract_items(ref_pols)
    cmp_list = extract_items(cmp_pols)

    def _pol_key(p: dict[str, Any]) -> str:
        tbl = str(p.get("table_name") or "").lower()
        pol = str(p.get("policy_name") or p.get("name") or "").lower()
        return f"{tbl}|{pol}"

    ref_map = {_pol_key(p): p for p in ref_list}
    cmp_map = {_pol_key(p): p for p in cmp_list}

    def _pol_diff(r: dict[str, Any], c: dict[str, Any]) -> dict[str, Any] | None:
        diffs: dict[str, Any] = {}
        for attr in ("command", "roles", "is_permissive"):
            if (attr in r or attr in c) and r.get(attr) != c.get(attr):
                diffs[attr] = {"expected": r.get(attr), "actual": c.get(attr)}

        for expr in ("using_expression", "check_expression"):
            r_ex = normalize_definition(str(r.get(expr) or ""))
            c_ex = normalize_definition(str(c.get(expr) or ""))
            if (expr in r or expr in c) and r_ex != c_ex:
                diffs[expr] = {"expected": r.get(expr), "actual": c.get(expr)}
        if diffs:
            res: dict[str, Any] = dict(diffs)
            res["expected"] = r
            res["actual"] = c
            return res
        return None

    missing, unexpected, mismatched = compare_mapped(ref_map, cmp_map, _pol_diff)
    return {"missing": missing, "unexpected": unexpected, "mismatched": mismatched}


def is_extension_version_compatible(
    expected: str | None,
    actual: str | None,
    policy: str = "exact",
) -> bool:
    """Check if extension versions match under the specified version policy."""
    if policy in ("ignore", "none", "off"):
        return True
    if expected == actual:
        return True
    if expected is None or actual is None:
        return False
    if policy == "exact":
        return str(expected).strip() == str(actual).strip()

    def _parse(ver: str) -> tuple[int | str, ...]:
        cleaned = ver.strip().lstrip("v")
        tokens = [p for p in re.split(r"[.\-_+]", cleaned) if p]
        parsed: list[int | str] = []
        for t in tokens:
            parsed.append(int(t) if t.isdigit() else t.lower())
        return tuple(parsed)

    exp_parts = _parse(str(expected))
    act_parts = _parse(str(actual))

    if not exp_parts or not act_parts:
        return str(expected).strip() == str(actual).strip()

    if policy in ("major", "ignore_minor"):
        return exp_parts[0] == act_parts[0]

    if policy in ("minor", "patch", "ignore_patch"):
        return exp_parts[:2] == act_parts[:2]

    return str(expected).strip() == str(actual).strip()


def compare_extensions(
    ref_exts: Any,
    cmp_exts: Any,
    *,
    version_policy: str = "exact",
) -> dict[str, Any]:
    """Compare database extensions including version, target schema, and relocatability."""
    ref_list = extract_items(ref_exts)
    cmp_list = extract_items(cmp_exts)

    ref_map = {str(e.get("extension_name") or e.get("name") or "").lower(): e for e in ref_list}
    cmp_map = {str(e.get("extension_name") or e.get("name") or "").lower(): e for e in cmp_list}

    def _ext_diff(r: dict[str, Any], c: dict[str, Any]) -> dict[str, Any] | None:
        diffs: dict[str, Any] = {}
        r_ver = r.get("version")
        c_ver = c.get("version")
        if not is_extension_version_compatible(r_ver, c_ver, policy=version_policy):
            diffs["version"] = {"expected": r_ver, "actual": c_ver}

        r_sch = r.get("schema") if "schema" in r else r.get("namespace")
        c_sch = c.get("schema") if "schema" in c else c.get("namespace")
        if (r_sch is not None or c_sch is not None) and r_sch != c_sch:
            diffs["schema"] = {"expected": r_sch, "actual": c_sch}

        r_reloc = r.get("relocatable") if "relocatable" in r else r.get("extrelocatable")
        c_reloc = c.get("relocatable") if "relocatable" in c else c.get("extrelocatable")
        if (r_reloc is not None or c_reloc is not None) and r_reloc != c_reloc:
            diffs["relocatable"] = {"expected": r_reloc, "actual": c_reloc}

        return diffs or None

    missing, unexpected, mismatched = compare_mapped(ref_map, cmp_map, _ext_diff)
    return {"missing": missing, "unexpected": unexpected, "mismatched": mismatched}


def compare_comments(ref_comments: Any, cmp_comments: Any) -> dict[str, Any]:
    """Compare database comments across schemas, tables, columns, routines, types, etc."""
    ref_list = extract_items(ref_comments)
    cmp_list = extract_items(cmp_comments)

    def _comment_key(item: dict[str, Any]) -> str:
        target_key = item.get("target_key")
        if target_key:
            return str(target_key).lower()
        obj_type = str(item.get("object_type") or "").lower()
        obj_name = str(item.get("object_name") or "").lower()
        sub_name = str(item.get("sub_object_name") or "").lower()
        if sub_name:
            return f"{obj_type}:{obj_name}.{sub_name}"
        return f"{obj_type}:{obj_name}"

    ref_map = {_comment_key(c): c for c in ref_list}
    cmp_map = {_comment_key(c): c for c in cmp_list}

    def _comment_diff(r: dict[str, Any], c: dict[str, Any]) -> dict[str, Any] | None:
        r_txt = str(r.get("comment") or "").strip()
        c_txt = str(c.get("comment") or "").strip()
        if r_txt != c_txt:
            return {"expected": r.get("comment"), "actual": c.get("comment")}
        return None

    missing, unexpected, mismatched = compare_mapped(ref_map, cmp_map, _comment_diff)
    return {"missing": missing, "unexpected": unexpected, "mismatched": mismatched}
