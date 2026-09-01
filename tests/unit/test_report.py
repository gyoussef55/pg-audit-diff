"""Unit tests for reporting, human-readable text summaries, and markdown output."""

from __future__ import annotations

from typing import Any

from pg_audit_diff.report import (
    REPORT_VERSION,
    build_report,
    classify_severity,
    extract_object_names,
    format_markdown_report,
    format_text_report,
    summarize_diff,
    summarize_severities,
)


def _sample_diff() -> dict[str, Any]:
    return {
        "tables": {
            "missing": {"users": {"table_name": "users"}, "orders": {"table_name": "orders"}},
            "unexpected": {},
            "mismatched": {},
        },
        "columns": {
            "missing": {},
            "unexpected": {},
            "mismatched": {
                "accounts": [{"balance": {"expected": "numeric(10,2)", "actual": "numeric(8,2)"}}]
            },
        },
        "indexes": {
            "missing": {},
            "unexpected": {
                "users_idx_email": {"table_name": "users", "index_name": "users_idx_email"}
            },
            "mismatched": {},
        },
        "primary_keys": {
            "missing": {},
            "unexpected": {},
            "mismatched": {},
        },
    }


def test_classify_severity() -> None:
    assert classify_severity("tables", "missing") == "blocking"
    assert classify_severity("tables", "mismatched") == "blocking"
    assert classify_severity("tables", "unexpected") == "warning"
    assert classify_severity("columns", "missing") == "blocking"
    assert classify_severity("indexes", "missing") == "warning"
    assert classify_severity("indexes", "unexpected") == "info"
    assert classify_severity("extensions", "unexpected") == "info"
    assert classify_severity("migrations", "missing") == "blocking"


def test_extract_object_names() -> None:
    diff = _sample_diff()
    tables_missing = extract_object_names("tables", "missing", diff["tables"]["missing"])
    assert "users" in tables_missing
    assert "orders" in tables_missing

    cols_mismatched = extract_object_names("columns", "mismatched", diff["columns"]["mismatched"])
    assert "accounts.balance" in cols_mismatched

    idx_unexpected = extract_object_names("indexes", "unexpected", diff["indexes"]["unexpected"])
    assert "users.users_idx_email" in idx_unexpected


def test_summarize_diff_and_severities() -> None:
    diff = _sample_diff()
    summary = summarize_diff(diff)
    assert summary["tables"]["missing"] == 2
    assert summary["columns"]["mismatched"] == 1
    assert summary["indexes"]["unexpected"] == 1

    severities = summarize_severities(diff)
    # tables missing = 2 (blocking), cols mismatch = 1 (blocking), idx unexpected = 1 (info)
    assert severities["blocking"] == 3
    assert severities["warning"] == 0
    assert severities["info"] == 1


def test_build_report_envelope() -> None:
    diff = _sample_diff()
    report = build_report(
        reference="prod_db",
        compared="stage_db",
        schema="public",
        diff=diff,
    )
    assert report["version"] == REPORT_VERSION
    assert report["version"] == 1
    assert report["reference"] == "prod_db"
    assert report["compared"] == "stage_db"
    assert report["schema"] == "public"
    assert report["has_drift"] is True
    assert report["has_blocking_drift"] is True
    assert report["summary"]["tables"]["missing"] == 2
    assert report["severity_counts"]["blocking"] == 3
    assert report["severity_counts"]["info"] == 1
    assert "diff" in report


def test_format_text_report_with_drift() -> None:
    diff = _sample_diff()
    report = build_report(
        reference="prod_db",
        compared="stage_db",
        schema="public",
        diff=diff,
    )
    text = format_text_report(report)
    assert "Schema compare: prod_db (reference) vs stage_db (compared)" in text
    assert "Schema: public" in text
    assert "Drift detected: True" in text
    assert "blocking=3" in text
    assert "tables: missing=2" in text
    assert "columns: missing=0 unexpected=0 mismatched=1" in text
    assert "Missing tables: users, orders" in text
    assert "Mismatched columns: accounts.balance" in text
    assert "Unexpected indexes: users.users_idx_email" in text


def test_format_text_report_clean() -> None:
    empty_diff: dict[str, Any] = {
        "tables": {"missing": {}, "unexpected": {}, "mismatched": {}},
        "columns": {"missing": {}, "unexpected": {}, "mismatched": {}},
    }
    report = build_report(
        reference="prod",
        compared="stage",
        schema="public",
        diff=empty_diff,
    )
    text = format_text_report(report)
    assert "Drift detected: False" in text
    assert "(all in sync)" in text


def test_format_markdown_report_with_drift() -> None:
    diff = _sample_diff()
    report = build_report(
        reference="prod_db",
        compared="stage_db",
        schema="public",
        diff=diff,
    )
    md = format_markdown_report(report)
    assert "## PostgreSQL Schema Diff Report" in md
    assert "- **Reference:** `prod_db`" in md
    assert "- **Compared:** `stage_db`" in md
    assert "🔴 **Blocking drift detected**" in md
    assert "| tables | 2 | 0 | 0 | 2 | 🔴 Blocking |" in md
    assert "| columns | 0 | 0 | 1 | 1 | 🔴 Blocking |" in md
    assert "| indexes | 0 | 1 | 0 | 1 | 🔵 Info |" in md
    assert "### Changed Objects" in md
    assert "| tables | Missing | `users` | 🔴 Blocking |" in md
    assert "| columns | Mismatched | `accounts.balance` | 🔴 Blocking |" in md


def test_format_markdown_report_clean() -> None:
    empty_diff: dict[str, Any] = {
        "tables": {"missing": {}, "unexpected": {}, "mismatched": {}},
    }
    report = build_report(
        reference="prod",
        compared="stage",
        schema="public",
        diff=empty_diff,
    )
    md = format_markdown_report(report)
    assert "🟢 **Schemas are in sync**" in md
    assert "🟢 In sync" in md


def test_check_constraint_counts_one_finding_per_constraint() -> None:
    """A single missing check constraint must not be counted once per attribute."""
    diff: dict[str, Any] = {
        "check_constraints": {
            "missing": {
                "orders|CHECK ((amount >= (0)::numeric))": {
                    "constraint_name": "check_amount_positive",
                    "constraint_type": "c",
                    "definition": "CHECK ((amount >= (0)::numeric))",
                    "is_valid": True,
                    "is_deferrable": False,
                    "table_name": "orders",
                }
            },
            "unexpected": {},
            "mismatched": {},
        }
    }
    report = build_report(reference="prod", compared="stage", schema="public", diff=diff)
    assert report["summary"]["check_constraints"]["missing"] == 1
    assert report["severity_counts"]["blocking"] == 1

    names = extract_object_names(
        "check_constraints", "missing", diff["check_constraints"]["missing"]
    )
    assert names == ["orders.check_amount_positive"]


def test_mismatched_objects_use_names_not_identity_keys() -> None:
    """Mismatched buckets wrap objects in expected/actual; labels must still be readable."""
    fk_key = "orders|user_id|public.users|id|cascade|no action"
    fk_object = {
        "table_name": "orders",
        "constraint_name": "orders_user_id_fkey",
        "columns": ["user_id"],
    }
    names = extract_object_names(
        "foreign_keys",
        "mismatched",
        {fk_key: {"expected": fk_object, "actual": {**fk_object, "is_valid": False}}},
    )
    assert names == ["orders.orders_user_id_fkey"]

    # Policy mismatches carry per-attribute diffs, so the identity key is the
    # only source for a label.
    policy_names = extract_object_names(
        "policies",
        "mismatched",
        {"users|users_tenant_isolation": {"command": {"expected": "ALL", "actual": "SELECT"}}},
    )
    assert policy_names == ["users.users_tenant_isolation"]


def test_duplicate_index_warnings_in_report() -> None:
    diff: dict[str, Any] = {
        "indexes": {
            "missing": {},
            "unexpected": {},
            "mismatched": {},
            "name_only": {},
            "duplicates": {
                "reference": [
                    {
                        "table_name": "users",
                        "columns": ["email"],
                        "index_names": ["idx_users_email", "idx_users_email_dup"],
                        "am_name": "btree",
                    }
                ],
                "compared": [],
            },
        }
    }
    report = build_report(
        reference="prod_db",
        compared="stage_db",
        schema="public",
        diff=diff,
    )
    assert len(report["warnings"]) == 1
    assert "Duplicate indexes in reference database on 'users(email)'" in report["warnings"][0]

    text = format_text_report(report)
    assert "Duplicate indexes in reference database" in text

    md = format_markdown_report(report)
    assert "### ⚠️ Warnings" in md
    assert "Duplicate indexes in reference database" in md
