"""Unit tests for extension refinements, table filters, and role support."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from pg_audit_diff.cli import app
from pg_audit_diff.connections import connect_readonly, verify_connection
from pg_audit_diff.diff import compare_snapshots, has_drift
from pg_audit_diff.diff_objects import compare_extensions, is_extension_version_compatible
from pg_audit_diff.snapshot import SnapshotOptions, filter_snapshot_tables

runner = CliRunner()


# ---------------------------------------------------------------------------
# 1. Extension Comparison Refinements (P5)
# ---------------------------------------------------------------------------


def test_extension_version_compatibility_helper() -> None:
    """Verify version compatibility under exact, major, minor, and ignore policies."""
    # exact
    assert is_extension_version_compatible("1.1", "1.1", policy="exact")
    assert not is_extension_version_compatible("1.1", "1.2", policy="exact")
    assert not is_extension_version_compatible("1.0.0", "1.0.1", policy="exact")

    # major (tolerate minor/patch differences)
    assert is_extension_version_compatible("1.1", "1.2", policy="major")
    assert is_extension_version_compatible("1.0.0", "1.9.9", policy="major")
    assert not is_extension_version_compatible("1.1", "2.0", policy="major")

    # minor (tolerate patch differences)
    assert is_extension_version_compatible("1.2.0", "1.2.5", policy="minor")
    assert not is_extension_version_compatible("1.2.0", "1.3.0", policy="minor")

    # ignore
    assert is_extension_version_compatible("1.0", "99.0", policy="ignore")
    assert is_extension_version_compatible(None, "1.0", policy="ignore")


def test_extension_diff_schema_and_relocatable_attributes() -> None:
    """Extension diffing detects schema target changes and relocatable drift."""
    ref_exts = {
        "pg_trgm": {
            "extension_name": "pg_trgm",
            "version": "1.6",
            "schema": "public",
            "relocatable": True,
        }
    }
    cmp_exts_diff = {
        "pg_trgm": {
            "extension_name": "pg_trgm",
            "version": "1.6",
            "schema": "extensions",
            "relocatable": False,
        }
    }

    res = compare_extensions(ref_exts, cmp_exts_diff, version_policy="exact")
    assert "pg_trgm" in res["mismatched"]
    diff = res["mismatched"]["pg_trgm"]
    assert diff["schema"] == {"expected": "public", "actual": "extensions"}
    assert diff["relocatable"] == {"expected": True, "actual": False}


def test_extension_diff_with_version_policies() -> None:
    """compare_snapshots respects extension_version_policy parameter."""
    ref = {
        "extensions": {
            "uuid-ossp": {
                "extension_name": "uuid-ossp",
                "version": "1.1",
                "schema": "public",
                "relocatable": True,
            }
        }
    }
    cmp = {
        "extensions": {
            "uuid-ossp": {
                "extension_name": "uuid-ossp",
                "version": "1.2",
                "schema": "public",
                "relocatable": True,
            }
        }
    }

    # Under 'exact', version mismatch is reported as drift
    diff_exact = compare_snapshots(ref, cmp, extension_version_policy="exact")
    assert has_drift(diff_exact)
    assert "uuid-ossp" in diff_exact["extensions"]["mismatched"]

    # Under 'major', minor version diff is tolerated
    diff_major = compare_snapshots(ref, cmp, extension_version_policy="major")
    assert not has_drift(diff_major)
    assert not diff_major["extensions"]["mismatched"]

    # Under 'ignore', all version diffs are tolerated
    diff_ignore = compare_snapshots(ref, cmp, extension_version_policy="ignore")
    assert not has_drift(diff_ignore)


# ---------------------------------------------------------------------------
# 2. Large-Catalog Scalability & Table Filters (P8)
# ---------------------------------------------------------------------------


def test_table_filter_pushdown_scopes_all_related_objects() -> None:
    """filter_snapshot_tables scopes tables, columns, indexes, constraints, triggers, policies, and sequences."""
    rich_snapshot: dict[str, Any] = {
        "snapshot_version": 1,
        "schema": "public",
        "tables": {
            "users": {"table_name": "users", "table_type": "table"},
            "orders": {"table_name": "orders", "table_type": "table"},
            "audit_log": {"table_name": "audit_log", "table_type": "table"},
        },
        "columns": {
            "users": [{"column_name": "id", "data_type": "uuid"}],
            "orders": [{"column_name": "id", "data_type": "uuid"}],
            "audit_log": [{"column_name": "id", "data_type": "uuid"}],
        },
        "pks": [
            {"table_name": "users", "constraint_name": "users_pkey"},
            {"table_name": "orders", "constraint_name": "orders_pkey"},
            {"table_name": "audit_log", "constraint_name": "audit_log_pkey"},
        ],
        "ucs": [
            {"table_name": "users", "constraint_name": "users_email_key"},
            {"table_name": "orders", "constraint_name": "orders_num_key"},
        ],
        "fks": [
            {"table_name": "orders", "constraint_name": "orders_user_fkey"},
            {"table_name": "audit_log", "constraint_name": "audit_user_fkey"},
        ],
        "indexes": [
            {"table_name": "users", "index_name": "idx_users_email"},
            {"table_name": "orders", "index_name": "idx_orders_user"},
            {"table_name": "audit_log", "index_name": "idx_audit_created"},
        ],
        "constraints": {
            "users": [{"constraint_name": "chk_users_age"}],
            "audit_log": [{"constraint_name": "chk_audit_level"}],
        },
        "triggers": {
            "public.users.trg": {"table_name": "users", "trigger_name": "trg_users"},
            "public.audit_log.trg": {"table_name": "audit_log", "trigger_name": "trg_audit"},
        },
        "policies": {
            "users.pol": {"table_name": "users", "policy_name": "users_isolation"},
            "orders.pol": {"table_name": "orders", "policy_name": "orders_isolation"},
        },
        "views": {
            "users_v": {"view_name": "users_v", "view_type": "view"},
            "audit_v": {"view_name": "audit_v", "view_type": "view"},
        },
        "sequences": {
            "users_id_seq": {"sequence_name": "users_id_seq", "owned_by_table": "users"},
            "audit_id_seq": {"sequence_name": "audit_id_seq", "owned_by_table": "audit_log"},
            "global_seq": {"sequence_name": "global_seq", "owned_by_table": None},
        },
    }

    # 1. Filter with include_tables = "^(users|orders)$"
    opts_include = SnapshotOptions(include_tables=r"^(users|orders)$")
    filtered_inc = filter_snapshot_tables(rich_snapshot, opts_include)

    assert set(filtered_inc["tables"].keys()) == {"users", "orders"}
    assert set(filtered_inc["columns"].keys()) == {"users", "orders"}
    assert {pk["table_name"] for pk in filtered_inc["pks"]} == {"users", "orders"}
    assert {uc["table_name"] for uc in filtered_inc["ucs"]} == {"users", "orders"}
    assert {fk["table_name"] for fk in filtered_inc["fks"]} == {"orders"}
    assert {idx["table_name"] for idx in filtered_inc["indexes"]} == {"users", "orders"}
    assert set(filtered_inc["constraints"].keys()) == {"users"}
    assert {v["table_name"] for v in filtered_inc["triggers"].values()} == {"users"}
    assert {p["table_name"] for p in filtered_inc["policies"].values()} == {"users", "orders"}
    assert "users_id_seq" in filtered_inc["sequences"]
    assert "global_seq" in filtered_inc["sequences"]
    assert "audit_id_seq" not in filtered_inc["sequences"]

    # 2. Filter with exclude_tables = "audit_.*"
    opts_exclude = SnapshotOptions(exclude_tables=r"audit_.*")
    filtered_exc = filter_snapshot_tables(rich_snapshot, opts_exclude)

    assert "audit_log" not in filtered_exc["tables"]
    assert "audit_log" not in filtered_exc["columns"]
    assert "audit_id_seq" not in filtered_exc["sequences"]
    assert "global_seq" in filtered_exc["sequences"]
    assert "users" in filtered_exc["tables"]


def test_cli_diff_with_include_and_exclude_tables(tmp_path: Path) -> None:
    """CLI diff command properly scopes snapshot comparison with --include-tables / --exclude-tables."""
    ref_snap = {
        "snapshot_version": 1,
        "schema": "public",
        "tables": {
            "users": {"table_name": "users", "table_type": "table"},
            "temp_data": {"table_name": "temp_data", "table_type": "table"},
        },
        "columns": {
            "users": [{"column_name": "id", "data_type": "uuid"}],
            "temp_data": [{"column_name": "id", "data_type": "int"}],
        },
    }
    cmp_snap = {
        "snapshot_version": 1,
        "schema": "public",
        "tables": {
            "users": {"table_name": "users", "table_type": "table"},
            "temp_data": {"table_name": "temp_data", "table_type": "table"},
        },
        "columns": {
            "users": [{"column_name": "id", "data_type": "uuid"}],
            "temp_data": [{"column_name": "id", "data_type": "text"}],  # Mismatch in temp_data
        },
    }

    ref_file = tmp_path / "ref.json"
    cmp_file = tmp_path / "cmp.json"
    ref_file.write_text(json.dumps(ref_snap))
    cmp_file.write_text(json.dumps(cmp_snap))

    # Without filter: drift detected in temp_data
    res1 = runner.invoke(
        app,
        ["diff", "--reference-snapshot", str(ref_file), "--compared-snapshot", str(cmp_file)],
    )
    assert res1.exit_code == 0
    payload1 = json.loads(res1.stdout)
    assert payload1["has_drift"] is True

    # With --exclude-tables "^temp_.*": drift in temp_data is excluded, report is clean!
    res2 = runner.invoke(
        app,
        [
            "diff",
            "--reference-snapshot",
            str(ref_file),
            "--compared-snapshot",
            str(cmp_file),
            "--exclude-tables",
            r"^temp_.*",
        ],
    )
    assert res2.exit_code == 0
    payload2 = json.loads(res2.stdout)
    assert payload2["has_drift"] is False


def test_cli_diff_with_extension_version_policy(tmp_path: Path) -> None:
    """CLI diff command accepts --extension-version-policy flag."""
    ref_snap = {
        "snapshot_version": 1,
        "schema": "public",
        "extensions": {"uuid-ossp": {"extension_name": "uuid-ossp", "version": "1.1"}},
    }
    cmp_snap = {
        "snapshot_version": 1,
        "schema": "public",
        "extensions": {"uuid-ossp": {"extension_name": "uuid-ossp", "version": "1.2"}},
    }

    ref_file = tmp_path / "ref.json"
    cmp_file = tmp_path / "cmp.json"
    ref_file.write_text(json.dumps(ref_snap))
    cmp_file.write_text(json.dumps(cmp_snap))

    # Exact -> drift
    res_exact = runner.invoke(
        app,
        [
            "diff",
            "--reference-snapshot",
            str(ref_file),
            "--compared-snapshot",
            str(cmp_file),
            "--extension-version-policy",
            "exact",
        ],
    )
    assert json.loads(res_exact.stdout)["has_drift"] is True

    # Major -> no drift
    res_major = runner.invoke(
        app,
        [
            "diff",
            "--reference-snapshot",
            str(ref_file),
            "--compared-snapshot",
            str(cmp_file),
            "--extension-version-policy",
            "major",
        ],
    )
    assert json.loads(res_major.stdout)["has_drift"] is False


# ---------------------------------------------------------------------------
# 3. Role & Least-Privilege Support (P10)
# ---------------------------------------------------------------------------


def test_connect_readonly_executes_set_role() -> None:
    """connect_readonly executes SET ROLE identifier when role parameter is passed."""
    mock_conn = MagicMock()
    with (
        patch("psycopg.connect", return_value=mock_conn),
        connect_readonly("postgresql://user@localhost/db", role="schema_auditor"),
    ):
        pass

    executed_sqls = [str(call[0][0]) for call in mock_conn.execute.call_args_list]
    assert any("SET ROLE" in s and "schema_auditor" in s for s in executed_sqls)
    assert any("application_name" in s for s in executed_sqls)
    assert any("statement_timeout" in s for s in executed_sqls)


def test_verify_connection_with_role() -> None:
    """verify_connection passes role to connect_readonly."""
    mock_conn = MagicMock()
    mock_conn.execute.return_value.fetchone.return_value = {"ok": 1}
    with patch("psycopg.connect", return_value=mock_conn):
        assert verify_connection("postgresql://user@localhost/db", role="auditor_role") is True
