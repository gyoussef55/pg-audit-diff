"""Unit tests for logical schema diff (no database)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pg_audit_diff.diff import compare_snapshots, has_drift
from pg_audit_diff.report import build_report, summarize_diff

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict[str, Any]:
    with open(FIXTURES / name) as handle:
        data: dict[str, Any] = json.load(handle)
        return data


def test_idempotence_no_drift_when_snapshots_match() -> None:
    """Comparing any snapshot against itself must yield zero drift (idempotence)."""
    for fixture_name in ("reference.json", "compared_clean.json"):
        snap = _load(fixture_name)
        diff = compare_snapshots(snap, snap)
        assert not has_drift(diff), f"Self-comparison had drift for {fixture_name}"
        summary = summarize_diff(diff)
        for section, counts in summary.items():
            assert (
                counts["missing"] == 0 and counts["unexpected"] == 0 and counts["mismatched"] == 0
            ), f"Expected 0 drift counts in {section} for {fixture_name}"


def test_symmetry_inverted_buckets() -> None:
    """compare(A, B) must equal compare(B, A) with missing and unexpected buckets swapped."""
    pairs = [
        ("reference.json", "compared_missing_table.json"),
        ("reference.json", "compared_extra_table.json"),
    ]
    for ref_name, cmp_name in pairs:
        a = _load(ref_name)
        b = _load(cmp_name)
        diff_ab = compare_snapshots(a, b)
        diff_ba = compare_snapshots(b, a)

        for section in (
            "tables",
            "columns",
            "primary_keys",
            "foreign_keys",
            "indexes",
            "views",
            "sequences",
        ):
            sec_ab = diff_ab.get(section, {})
            sec_ba = diff_ba.get(section, {})

            ab_missing = sec_ab.get(
                "missing", {} if isinstance(sec_ab.get("missing"), dict) else []
            )
            ba_unexpected = sec_ba.get(
                "unexpected", {} if isinstance(sec_ba.get("unexpected"), dict) else []
            )
            ab_unexpected = sec_ab.get(
                "unexpected", {} if isinstance(sec_ab.get("unexpected"), dict) else []
            )
            ba_missing = sec_ba.get(
                "missing", {} if isinstance(sec_ba.get("missing"), dict) else []
            )

            # Check counts of missing in A->B match unexpected in B->A
            assert len(ab_missing) == len(ba_unexpected), (
                f"Symmetry failed for {section}: missing in A->B ({len(ab_missing)}) "
                f"!= unexpected in B->A ({len(ba_unexpected)})"
            )
            assert len(ab_unexpected) == len(ba_missing), (
                f"Symmetry failed for {section}: unexpected in A->B ({len(ab_unexpected)}) "
                f"!= missing in B->A ({len(ba_missing)})"
            )


def test_missing_and_unexpected_table_detected() -> None:
    ref = _load("reference.json")
    cmp_missing = _load("compared_missing_table.json")
    diff_missing = compare_snapshots(ref, cmp_missing)
    assert has_drift(diff_missing)
    assert "orders" in diff_missing["tables"]["missing"]

    cmp_extra = _load("compared_extra_table.json")
    diff_extra = compare_snapshots(ref, cmp_extra)
    assert has_drift(diff_extra)
    assert "orphan_table" in diff_extra["tables"]["unexpected"]


def test_index_logical_comparison_am_and_predicate() -> None:
    """Index comparison must catch access method changes and predicate changes."""
    ref = _load("reference.json")
    cmp_idx = _load("compared_partial_index.json")
    diff = compare_snapshots(ref, cmp_idx)

    assert has_drift(diff)
    # The btree vs gin index on email is missing from compared and unexpected in compared
    # and the predicate change on orders is also detected
    assert len(diff["indexes"]["missing"]) > 0 or len(diff["indexes"]["mismatched"]) > 0


def test_index_predicate_change_reported_as_mismatched_not_missing() -> None:
    """Predicate-only index changes should land in mismatched, not missing+unexpected."""
    ref = _load("reference.json")
    cmp_idx = _load("compared_partial_index.json")
    diff = compare_snapshots(ref, cmp_idx)

    assert "idx_orders_active_user" in diff["indexes"]["mismatched"]
    assert "idx_orders_active_user" not in diff["indexes"]["missing"]
    assert "idx_orders_active_user" not in diff["indexes"]["unexpected"]


def test_index_name_only_difference_detected() -> None:
    """Index rename with identical logical structure should be flagged in name_only."""
    ref = _load("reference.json")
    cmp_snap = json.loads(json.dumps(ref))
    # Rename index without changing table, columns, unique, am, predicate
    cmp_snap["indexes"][0]["index_name"] = "idx_users_email_renamed"

    diff = compare_snapshots(ref, cmp_snap)
    assert len(diff["indexes"]["name_only"]) == 1
    assert len(diff["indexes"]["missing"]) == 0
    assert len(diff["indexes"]["unexpected"]) == 0
    # A rename alone is not drift; it only counts when renames are explicitly included.
    assert not has_drift(diff)
    assert has_drift(diff, include_renames=True)


def test_colliding_index_keys_are_never_dropped() -> None:
    """Extra indexes sharing one logical key must be reported, not silently discarded."""
    ref = _load("reference.json")
    cmp_snap = json.loads(json.dumps(ref))
    duplicate = json.loads(json.dumps(ref["indexes"][0]))
    duplicate["index_name"] = "idx_users_email_duplicate"
    ref["indexes"].append(duplicate)

    diff = compare_snapshots(ref, cmp_snap)
    assert has_drift(diff)
    assert "idx_users_email_duplicate" in diff["indexes"]["missing"]

    inverted = compare_snapshots(cmp_snap, ref)
    assert "idx_users_email_duplicate" in inverted["indexes"]["unexpected"]


def test_duplicate_indexes_detected_and_reported() -> None:
    """Duplicate indexes on the same side must be tracked under duplicates."""
    ref = _load("reference.json")
    cmp_snap = json.loads(json.dumps(ref))
    duplicate = json.loads(json.dumps(ref["indexes"][0]))
    duplicate["index_name"] = "idx_users_email_duplicate"
    ref["indexes"].append(duplicate)

    diff = compare_snapshots(ref, cmp_snap)
    assert "duplicates" in diff["indexes"]
    assert len(diff["indexes"]["duplicates"]["reference"]) == 1
    ref_dupe = diff["indexes"]["duplicates"]["reference"][0]
    assert ref_dupe["table_name"] == "users"
    assert "idx_users_email" in ref_dupe["index_names"]
    assert "idx_users_email_duplicate" in ref_dupe["index_names"]
    assert len(diff["indexes"]["duplicates"]["compared"]) == 0


def test_index_column_ordering_difference_detected() -> None:
    """A DESC/ASC change on the same column must be reported as a mismatch."""
    ref = _load("reference.json")
    cmp_snap = json.loads(json.dumps(ref))
    cmp_snap["indexes"][0]["column_details"] = ["email:text_ops:desc:nulls_first:default"]

    diff = compare_snapshots(ref, cmp_snap)
    assert has_drift(diff)
    assert "column_details" in diff["indexes"]["mismatched"]["idx_users_email"]["diffs"]


def test_column_type_precision_and_case_sensitive_default() -> None:
    """Column comparison must detect precision mismatch and case-sensitive defaults."""
    ref = _load("reference.json")
    cmp_col = _load("compared_column_mismatch.json")
    diff = compare_snapshots(ref, cmp_col)

    assert has_drift(diff)
    user_mismatches = diff["columns"]["mismatched"]["users"]
    order_mismatches = diff["columns"]["mismatched"]["orders"]

    # Verify case-sensitive default difference ('ACTIVE' vs 'active')
    status_diff = next(item["status"] for item in user_mismatches if "status" in item)
    assert status_diff["column_default"]["expected"] == "'ACTIVE'::user_status"
    assert status_diff["column_default"]["actual"] == "'active'::user_status"

    # Verify type precision difference (numeric(10,2) vs numeric(19,4))
    amount_diff = next(item["amount"] for item in order_mismatches if "amount" in item)
    assert amount_diff["data_type"]["expected"] == "numeric(10,2)"
    assert amount_diff["data_type"]["actual"] == "numeric(19,4)"


def test_view_definitions_diff() -> None:
    """View definition differences must be reported in views.mismatched."""
    ref = _load("reference.json")
    cmp_view = _load("compared_view_diff.json")
    diff = compare_snapshots(ref, cmp_view)

    assert has_drift(diff)
    assert "active_users" in diff["views"]["mismatched"]
    assert "status" in diff["views"]["mismatched"]["active_users"]["actual"]["definition"]


def test_sequence_attributes_diff() -> None:
    """Sequence data_type / max_value differences must be reported in sequences.mismatched."""
    ref = _load("reference.json")
    cmp_seq = _load("compared_sequence_diff.json")
    diff = compare_snapshots(ref, cmp_seq)

    assert has_drift(diff)
    assert "orders_id_seq" in diff["sequences"]["mismatched"]
    assert diff["sequences"]["mismatched"]["orders_id_seq"]["data_type"]["expected"] == "bigint"
    assert diff["sequences"]["mismatched"]["orders_id_seq"]["data_type"]["actual"] == "integer"


def test_rls_policy_diff() -> None:
    """RLS policy using/with_check expression differences must be reported in mismatched."""
    ref = _load("reference.json")
    cmp_pol = _load("compared_policy_diff.json")
    diff = compare_snapshots(ref, cmp_pol)

    assert has_drift(diff)
    pol_key = "users|users_tenant_isolation"
    assert pol_key in diff["policies"]["mismatched"]
    assert "using_expression" in diff["policies"]["mismatched"][pol_key]


def test_trigger_enabled_disabled_diff() -> None:
    """Trigger enabled vs disabled status must be reported in triggers.mismatched."""
    ref = _load("reference.json")
    cmp_trg = _load("compared_trigger_disabled.json")
    diff = compare_snapshots(ref, cmp_trg)

    assert has_drift(diff)
    trg_key = "public.users.trg_users_audit"
    assert trg_key in diff["triggers"]["mismatched"]
    assert diff["triggers"]["mismatched"][trg_key]["enabled"]["expected"] is True
    assert diff["triggers"]["mismatched"][trg_key]["enabled"]["actual"] is False


def test_enum_ordering_vs_values_diff() -> None:
    """Enum order differences should be flagged as order_only mismatch."""
    ref = _load("reference.json")
    cmp_enum = _load("compared_enum_reordered.json")
    diff = compare_snapshots(ref, cmp_enum)

    assert has_drift(diff)
    assert "user_status" in diff["types"]["mismatched"]
    mismatch_info = diff["types"]["mismatched"]["user_status"]
    assert mismatch_info["order_only"] is True
    assert mismatch_info["expected"] == ["PENDING", "ACTIVE", "SUSPENDED", "DELETED"]
    assert mismatch_info["actual"] == ["ACTIVE", "PENDING", "SUSPENDED", "DELETED"]


def test_unvalidated_foreign_key_diff() -> None:
    """Foreign key validity state difference (is_valid: true vs false) must be reported."""
    ref = _load("reference.json")
    cmp_fk = _load("compared_unvalidated_fk.json")
    diff = compare_snapshots(ref, cmp_fk)

    assert has_drift(diff)
    fk_key = "orders|user_id|public.users|id|cascade|no action"
    assert fk_key in diff["foreign_keys"]["mismatched"]
    assert diff["foreign_keys"]["mismatched"][fk_key]["expected"]["is_valid"] is True
    assert diff["foreign_keys"]["mismatched"][fk_key]["actual"]["is_valid"] is False


def test_check_and_exclusion_constraints_symmetry() -> None:
    snap_a = {
        "constraints": [
            {
                "contype": "c",
                "table_name": "products",
                "constraint_name": "chk_price_a",
                "definition": "CHECK (price > 0)",
                "is_valid": True,
            },
            {
                "contype": "x",
                "table_name": "bookings",
                "constraint_name": "excl_booking_a",
                "definition": "EXCLUDE USING gist (during WITH &&)",
                "is_valid": True,
            },
        ]
    }
    snap_b = {
        "constraints": [
            {
                "contype": "c",
                "table_name": "products",
                "constraint_name": "chk_price_b",
                "definition": "CHECK   (price > 0) ",
                "is_valid": True,
            },
            {
                "contype": "x",
                "table_name": "bookings",
                "constraint_name": "excl_booking_b",
                "definition": "EXCLUDE USING gist (during WITH &&)",
                "is_valid": True,
            },
        ]
    }
    diff_ab = compare_snapshots(snap_a, snap_b)
    assert not has_drift(diff_ab)
    diff_ba = compare_snapshots(snap_b, snap_a)
    assert not has_drift(diff_ba)


def test_exclusion_constraint_drift_is_reported() -> None:
    """Exclusion constraints are collected, so a difference must reach the diff output."""
    snap_a = {
        "constraints": {
            "bookings": [
                {
                    "constraint_name": "excl_booking",
                    "constraint_type": "x",
                    "definition": "EXCLUDE USING gist (during WITH &&)",
                    "is_valid": True,
                }
            ]
        }
    }
    snap_b: dict[str, Any] = {"constraints": {"bookings": []}}

    diff = compare_snapshots(snap_a, snap_b)
    assert has_drift(diff)
    assert len(diff["exclusion_constraints"]["missing"]) == 1
    assert len(diff["check_constraints"]["missing"]) == 0

    inverted = compare_snapshots(snap_b, snap_a)
    assert len(inverted["exclusion_constraints"]["unexpected"]) == 1


def test_domains_comparison() -> None:
    ref = {
        "types": {
            "us_postal_code": {
                "type_name": "us_postal_code",
                "type_kind": "domain",
                "base_type": "text",
                "is_nullable": "NO",
                "default_value": None,
                "constraints": ["CHECK (VALUE ~ '^\\d{5}$')"],
            }
        }
    }
    cmp = {
        "types": {
            "us_postal_code": {
                "type_name": "us_postal_code",
                "type_kind": "domain",
                "base_type": "varchar(10)",
                "is_nullable": "NO",
                "default_value": None,
                "constraints": ["CHECK (VALUE ~ '^\\d{5}$')"],
            }
        }
    }
    diff = compare_snapshots(ref, cmp)
    assert has_drift(diff)
    assert "us_postal_code" in diff["types"]["mismatched"]


def test_functions_attributes_and_volatility_diff() -> None:
    ref = {
        "functions": {
            "public.calc(int)": {
                "function_key": "public.calc(int)",
                "return_type": "int",
                "prokind": "f",
                "volatility": "i",
                "is_security_definer": False,
                "is_leakproof": False,
                "parallel_safety": "u",
                "definition": (
                    "CREATE FUNCTION public.calc(int) RETURNS int AS "
                    "$$ SELECT $1 + 1 $$ LANGUAGE sql"
                ),
            }
        }
    }
    cmp = {
        "functions": {
            "public.calc(int)": {
                "function_key": "public.calc(int)",
                "return_type": "int",
                "prokind": "f",
                "volatility": "v",
                "is_security_definer": False,
                "is_leakproof": False,
                "parallel_safety": "u",
                "definition": (
                    "CREATE FUNCTION public.calc(int) RETURNS int AS "
                    "$$ SELECT $1 + 1 $$ LANGUAGE sql"
                ),
            }
        }
    }
    diff = compare_snapshots(ref, cmp)
    assert has_drift(diff)
    assert "public.calc(int)" in diff["functions"]["mismatched"]


def test_migrations_checksum_mismatch() -> None:
    ref = {
        "migrations": {
            "20260801000000_init": {
                "name": "20260801000000_init",
                "checksum": "sha256:abc",
                "timestamp": "2026-08-01T00:00:00Z",
            }
        }
    }
    cmp = {
        "migrations": {
            "20260801000000_init": {
                "name": "20260801000000_init",
                "checksum": "sha256:corrupted",
                "timestamp": "2026-08-01T00:00:00Z",
            }
        }
    }
    diff = compare_snapshots(ref, cmp)
    assert has_drift(diff)
    assert "20260801000000_init" in diff["migrations"]["mismatched"]


def test_report_envelope() -> None:
    ref = _load("reference.json")
    cmp_snap = _load("compared_missing_table.json")
    diff = compare_snapshots(ref, cmp_snap)
    report = build_report(reference="ref", compared="cmp", schema="public", diff=diff)
    assert report["version"] == 1
    assert report["has_drift"] is True
    assert "diff" in report
    assert report["summary"]["tables"]["missing"] == 1


def test_disabled_row_level_security_is_reported_even_when_policies_match() -> None:
    """Policies are inert unless RLS is enabled, so the flag itself must be compared.

    A table can carry byte-identical policies on both sides while having RLS switched
    off in one environment, which silently grants unrestricted access.
    """
    secured = {
        "tables": {
            "accounts": {
                "table_name": "accounts",
                "table_type": "table",
                "rls_enabled": True,
                "rls_forced": False,
            }
        }
    }
    unsecured = {
        "tables": {
            "accounts": {
                "table_name": "accounts",
                "table_type": "table",
                "rls_enabled": False,
                "rls_forced": False,
            }
        }
    }

    diff = compare_snapshots(secured, unsecured)

    assert diff["tables"]["mismatched"]["accounts"]["rls_enabled"] == {
        "expected": True,
        "actual": False,
    }
    assert has_drift(diff)


def test_forced_row_level_security_difference_is_reported() -> None:
    """FORCE ROW LEVEL SECURITY changes whether the table owner bypasses policies."""
    forced = {"tables": {"ledger": {"table_name": "ledger", "rls_forced": True}}}
    unforced = {"tables": {"ledger": {"table_name": "ledger", "rls_forced": False}}}

    diff = compare_snapshots(forced, unforced)

    assert diff["tables"]["mismatched"]["ledger"]["rls_forced"] == {
        "expected": True,
        "actual": False,
    }
