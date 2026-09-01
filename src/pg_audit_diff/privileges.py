"""Object privileges and ownership comparison with role mapping support."""

from __future__ import annotations

from typing import Any

from pg_audit_diff.diff_helpers import compare_mapped


def normalize_role(role: str | None, role_mapping: dict[str, str] | None = None) -> str:
    """Normalize a role name by applying configured role mapping if present."""
    if role is None:
        return ""
    name = str(role).strip()
    if role_mapping and name in role_mapping:
        return role_mapping[name]
    return name


def _flatten_privileges(data: Any) -> dict[str, dict[str, Any]]:
    """Flatten schema/tables/routines nested privileges into a uniform key->object dict."""
    if not isinstance(data, dict):
        return {}

    flattened: dict[str, dict[str, Any]] = {}

    # Handle nested structure: {"schema": {...}, "tables": {...}, "routines": {...}}
    if "schema" in data and isinstance(data["schema"], dict):
        sch_obj = data["schema"]
        s_name = str(sch_obj.get("object_name") or sch_obj.get("name") or "schema").lower()
        flattened[f"schema:{s_name}"] = sch_obj

    if "tables" in data and isinstance(data["tables"], dict):
        for t_name, t_obj in data["tables"].items():
            if isinstance(t_obj, dict):
                obj_name = str(t_obj.get("object_name") or t_name).lower()
                flattened[f"table:{obj_name}"] = t_obj

    if "routines" in data and isinstance(data["routines"], dict):
        for r_name, r_obj in data["routines"].items():
            if isinstance(r_obj, dict):
                obj_name = str(r_obj.get("object_name") or r_name).lower()
                flattened[f"routine:{obj_name}"] = r_obj

    # Handle already flat dictionary if neither schema/tables/routines was found
    if not flattened and data:
        for k, v in data.items():
            if isinstance(v, dict):
                flattened[str(k).lower()] = v

    return flattened


def _grant_key(
    grant: dict[str, Any], role_mapping: dict[str, str] | None = None
) -> tuple[str, str, bool]:
    grantee = normalize_role(str(grant.get("grantee") or ""), role_mapping).lower()
    priv = str(grant.get("privilege_type") or "").upper()
    grantable = bool(grant.get("is_grantable", False))
    return (grantee, priv, grantable)


def compare_privileges(
    ref_privileges: Any,
    cmp_privileges: Any,
    *,
    role_mapping: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Compare ownership and ACL grants between reference and compared snapshots."""
    ref_map = _flatten_privileges(ref_privileges)
    cmp_map = _flatten_privileges(cmp_privileges)

    if not ref_map and not cmp_map:
        return {"missing": {}, "unexpected": {}, "mismatched": {}}

    def _priv_diff(r: dict[str, Any], c: dict[str, Any]) -> dict[str, Any] | None:
        diffs: dict[str, Any] = {}

        # 1. Compare ownership
        r_owner = str(r.get("owner") or "")
        c_owner = str(c.get("owner") or "")
        expected_owner_mapped = normalize_role(r_owner, role_mapping)
        if expected_owner_mapped.lower() != c_owner.lower():
            diffs["owner"] = {
                "expected": r_owner,
                "actual": c_owner,
            }

        # 2. Compare ACL grants
        r_acl = r.get("acl") or []
        c_acl = c.get("acl") or []
        r_grants = [g for g in r_acl if isinstance(g, dict)]
        c_grants = [g for g in c_acl if isinstance(g, dict)]

        r_grant_keys = {_grant_key(g, role_mapping): g for g in r_grants}
        c_grant_keys = {_grant_key(g, None): g for g in c_grants}

        missing_grants = [
            r_grant_keys[k] for k in sorted(r_grant_keys.keys() - c_grant_keys.keys())
        ]
        unexpected_grants = [
            c_grant_keys[k] for k in sorted(c_grant_keys.keys() - r_grant_keys.keys())
        ]

        if missing_grants or unexpected_grants:
            diffs["acl"] = {
                "missing_grants": missing_grants,
                "unexpected_grants": unexpected_grants,
                "expected": r_acl,
                "actual": c_acl,
            }

        if diffs:
            res = dict(diffs)
            res["expected"] = r
            res["actual"] = c
            return res
        return None

    missing, unexpected, mismatched = compare_mapped(ref_map, cmp_map, _priv_diff)
    return {"missing": missing, "unexpected": unexpected, "mismatched": mismatched}
