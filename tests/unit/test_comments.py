"""Unit tests for database comments comparison."""

from __future__ import annotations

from pg_audit_diff.diff import compare_snapshots, has_drift
from pg_audit_diff.diff_objects import compare_comments


def test_compare_comments_detects_missing_unexpected_and_mismatched() -> None:
    ref = {
        "table:users": {
            "object_type": "table",
            "object_name": "users",
            "comment": "User accounts table",
        },
        "column:users.email": {
            "object_type": "column",
            "object_name": "users",
            "sub_object_name": "email",
            "comment": "Primary login email",
        },
        "function:calculate_tax(numeric)": {
            "object_type": "function",
            "object_name": "calculate_tax(numeric)",
            "comment": "Calculates sales tax",
        },
    }

    cmp = {
        "table:users": {
            "object_type": "table",
            "object_name": "users",
            "comment": "User accounts table modified",
        },
        "column:users.email": {
            "object_type": "column",
            "object_name": "users",
            "sub_object_name": "email",
            "comment": "Primary login email",
        },
        "table:orders": {
            "object_type": "table",
            "object_name": "orders",
            "comment": "Orders storage",
        },
    }

    diff = compare_comments(ref, cmp)

    assert "function:calculate_tax(numeric)" in diff["missing"]
    assert "table:orders" in diff["unexpected"]
    assert "table:users" in diff["mismatched"]
    assert diff["mismatched"]["table:users"] == {
        "expected": "User accounts table",
        "actual": "User accounts table modified",
    }


def test_compare_snapshots_includes_comments_drift() -> None:
    ref_snap = {
        "snapshot_version": 1,
        "comments": {
            "table:users": {
                "object_type": "table",
                "object_name": "users",
                "comment": "Auth users",
            }
        },
    }
    cmp_snap = {
        "snapshot_version": 1,
        "comments": {
            "table:users": {
                "object_type": "table",
                "object_name": "users",
                "comment": "Changed auth users",
            }
        },
    }

    diff = compare_snapshots(ref_snap, cmp_snap)
    assert has_drift(diff)
    assert "table:users" in diff["comments"]["mismatched"]
