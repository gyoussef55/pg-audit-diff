"""Unit tests for object privileges, ownership tracking, and role mappings."""

from __future__ import annotations

from typing import Any

from pg_audit_diff.diff import compare_snapshots, has_drift
from pg_audit_diff.privileges import compare_privileges, normalize_role


def test_normalize_role_mapping() -> None:
    mapping = {"prod_app": "stage_app", "prod_admin": "stage_admin"}
    assert normalize_role("prod_app", mapping) == "stage_app"
    assert normalize_role("prod_admin", mapping) == "stage_admin"
    assert normalize_role("other_role", mapping) == "other_role"
    assert normalize_role(None, mapping) == ""


def test_privileges_owner_mismatch_detected() -> None:
    ref = {
        "privileges": {
            "tables": {
                "users": {
                    "object_name": "users",
                    "object_type": "table",
                    "owner": "app_owner",
                    "acl": [],
                }
            }
        }
    }
    cmp_snap = {
        "privileges": {
            "tables": {
                "users": {
                    "object_name": "users",
                    "object_type": "table",
                    "owner": "postgres",  # owner differs
                    "acl": [],
                }
            }
        }
    }
    diff = compare_snapshots(ref, cmp_snap)
    assert has_drift(diff)
    assert "table:users" in diff["privileges"]["mismatched"]
    assert diff["privileges"]["mismatched"]["table:users"]["owner"]["expected"] == "app_owner"
    assert diff["privileges"]["mismatched"]["table:users"]["owner"]["actual"] == "postgres"


def test_privileges_with_role_mapping_satisfies_drift() -> None:
    ref = {
        "privileges": {
            "tables": {
                "users": {
                    "object_name": "users",
                    "object_type": "table",
                    "owner": "prod_owner",
                    "acl": [
                        {
                            "grantee": "prod_reader",
                            "grantor": "prod_owner",
                            "privilege_type": "SELECT",
                            "is_grantable": False,
                        }
                    ],
                }
            }
        }
    }
    cmp_snap = {
        "privileges": {
            "tables": {
                "users": {
                    "object_name": "users",
                    "object_type": "table",
                    "owner": "dev_owner",
                    "acl": [
                        {
                            "grantee": "dev_reader",
                            "grantor": "dev_owner",
                            "privilege_type": "SELECT",
                            "is_grantable": False,
                        }
                    ],
                }
            }
        }
    }

    # Without role mapping -> drift detected
    diff_unmapped = compare_snapshots(ref, cmp_snap)
    assert has_drift(diff_unmapped)
    assert "table:users" in diff_unmapped["privileges"]["mismatched"]

    # With role mapping -> no drift!
    role_map = {"prod_owner": "dev_owner", "prod_reader": "dev_reader"}
    diff_mapped = compare_snapshots(ref, cmp_snap, role_mapping=role_map)
    assert not has_drift(diff_mapped)
    assert not diff_mapped["privileges"]["mismatched"]


def test_privileges_acl_missing_and_unexpected_grants() -> None:
    ref = {
        "privileges": {
            "tables": {
                "orders": {
                    "object_name": "orders",
                    "object_type": "table",
                    "owner": "postgres",
                    "acl": [
                        {
                            "grantee": "app_user",
                            "grantor": "postgres",
                            "privilege_type": "SELECT",
                            "is_grantable": False,
                        },
                        {
                            "grantee": "app_user",
                            "grantor": "postgres",
                            "privilege_type": "INSERT",
                            "is_grantable": False,
                        },
                    ],
                }
            }
        }
    }
    cmp_snap = {
        "privileges": {
            "tables": {
                "orders": {
                    "object_name": "orders",
                    "object_type": "table",
                    "owner": "postgres",
                    "acl": [
                        {
                            "grantee": "app_user",
                            "grantor": "postgres",
                            "privilege_type": "SELECT",
                            "is_grantable": False,
                        },
                        {
                            "grantee": "analytics_user",
                            "grantor": "postgres",
                            "privilege_type": "SELECT",
                            "is_grantable": False,
                        },
                    ],
                }
            }
        }
    }

    diff = compare_snapshots(ref, cmp_snap)
    assert has_drift(diff)
    assert "table:orders" in diff["privileges"]["mismatched"]
    mismatch = diff["privileges"]["mismatched"]["table:orders"]["acl"]
    assert len(mismatch["missing_grants"]) == 1
    assert mismatch["missing_grants"][0]["privilege_type"] == "INSERT"
    assert len(mismatch["unexpected_grants"]) == 1
    assert mismatch["unexpected_grants"][0]["grantee"] == "analytics_user"


def test_privileges_routines_and_schema() -> None:
    ref = {
        "privileges": {
            "schema": {
                "object_name": "public",
                "object_type": "schema",
                "owner": "postgres",
                "acl": [
                    {
                        "grantee": "PUBLIC",
                        "grantor": "postgres",
                        "privilege_type": "USAGE",
                        "is_grantable": False,
                    }
                ],
            },
            "routines": {
                "audit_fn()": {
                    "object_name": "audit_fn()",
                    "routine_name": "audit_fn",
                    "owner": "postgres",
                    "acl": [
                        {
                            "grantee": "app_user",
                            "grantor": "postgres",
                            "privilege_type": "EXECUTE",
                            "is_grantable": False,
                        }
                    ],
                }
            },
        }
    }
    cmp_snap: dict[str, Any] = {
        "privileges": {
            "schema": {
                "object_name": "public",
                "object_type": "schema",
                "owner": "postgres",
                "acl": [],  # missing USAGE grant
            },
            "routines": {},  # missing routine privileges
        }
    }
    diff = compare_snapshots(ref, cmp_snap)
    assert has_drift(diff)
    assert "schema:public" in diff["privileges"]["mismatched"]
    assert "routine:audit_fn()" in diff["privileges"]["missing"]


def test_privileges_idempotence_and_symmetry() -> None:
    privs_a = {
        "tables": {
            "t1": {
                "object_name": "t1",
                "owner": "alice",
                "acl": [{"grantee": "bob", "privilege_type": "SELECT", "is_grantable": False}],
            }
        }
    }
    privs_b = {
        "tables": {
            "t1": {
                "object_name": "t1",
                "owner": "carol",
                "acl": [{"grantee": "dave", "privilege_type": "SELECT", "is_grantable": False}],
            }
        }
    }

    # Idempotence
    diff_self = compare_privileges(privs_a, privs_a)
    assert not diff_self["missing"]
    assert not diff_self["unexpected"]
    assert not diff_self["mismatched"]

    # Symmetry
    diff_ab = compare_privileges(privs_a, privs_b)
    diff_ba = compare_privileges(privs_b, privs_a)
    assert len(diff_ab["mismatched"]) == len(diff_ba["mismatched"])
    assert diff_ab["mismatched"]["table:t1"]["owner"]["expected"] == "alice"
    assert diff_ab["mismatched"]["table:t1"]["owner"]["actual"] == "carol"
    assert diff_ba["mismatched"]["table:t1"]["owner"]["expected"] == "carol"
    assert diff_ba["mismatched"]["table:t1"]["owner"]["actual"] == "alice"
