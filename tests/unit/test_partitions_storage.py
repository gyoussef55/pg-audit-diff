"""Unit tests for partitioning, storage & persistence, server context, and multi-schema."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pg_audit_diff.diff import compare_snapshots, has_drift
from pg_audit_diff.diff_helpers import compare_columns, compare_table_attrs
from pg_audit_diff.report import build_report, format_markdown_report, format_text_report
from pg_audit_diff.snapshot import SnapshotOptions, filter_snapshot_tables

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict[str, Any]:
    with open(FIXTURES / name) as handle:
        data: dict[str, Any] = json.load(handle)
        return data


def test_partitioning_key_and_bound_diff() -> None:
    """Detect partition key, bound, and parent/child relationship differences."""
    ref_snap = {
        "snapshot_version": 1,
        "tables": {
            "measurement": {
                "table_name": "measurement",
                "table_type": "partitioned_table",
                "is_partitioned": True,
                "is_partition": False,
                "partition_key": "RANGE (logdate)",
                "partition_bound": None,
                "parent_table": None,
            },
            "measurement_y2026m01": {
                "table_name": "measurement_y2026m01",
                "table_type": "table",
                "is_partitioned": False,
                "is_partition": True,
                "partition_key": None,
                "partition_bound": "FOR VALUES FROM ('2026-01-01') TO ('2026-02-01')",
                "parent_table": "measurement",
                "parent_schema": "public",
            },
        },
        "columns": {},
        "pks": [],
        "ucs": [],
        "fks": [],
        "indexes": [],
    }

    cmp_snap = {
        "snapshot_version": 1,
        "tables": {
            "measurement": {
                "table_name": "measurement",
                "table_type": "partitioned_table",
                "is_partitioned": True,
                "is_partition": False,
                "partition_key": "LIST (city_id)",  # Partition key mismatch
                "partition_bound": None,
                "parent_table": None,
            },
            "measurement_y2026m01": {
                "table_name": "measurement_y2026m01",
                "table_type": "table",
                "is_partitioned": False,
                "is_partition": True,
                "partition_key": None,
                "partition_bound": "FOR VALUES FROM ('2026-01-01') TO ('2026-03-01')",  # Bound mismatch
                "parent_table": "measurement",
                "parent_schema": "public",
            },
        },
        "columns": {},
        "pks": [],
        "ucs": [],
        "fks": [],
        "indexes": [],
    }

    diff = compare_snapshots(ref_snap, cmp_snap)
    assert has_drift(diff)
    assert "measurement" in diff["tables"]["mismatched"]
    assert "partition_key" in diff["tables"]["mismatched"]["measurement"]
    assert (
        diff["tables"]["mismatched"]["measurement"]["partition_key"]["expected"]
        == "RANGE (logdate)"
    )
    assert (
        diff["tables"]["mismatched"]["measurement"]["partition_key"]["actual"] == "LIST (city_id)"
    )

    assert "measurement_y2026m01" in diff["tables"]["mismatched"]
    assert "partition_bound" in diff["tables"]["mismatched"]["measurement_y2026m01"]


def test_table_storage_and_persistence_diff() -> None:
    """Detect unlogged vs permanent tables, autovacuum reloptions, and tablespaces."""
    ref_table = {
        "table_name": "cache_entries",
        "table_type": "table",
        "persistence": "unlogged",
        "reloptions": ["autovacuum_enabled=false", "fillfactor=70"],
        "tablespace": "fast_ssd",
    }
    cmp_table = {
        "table_name": "cache_entries",
        "table_type": "table",
        "persistence": "permanent",
        "reloptions": ["autovacuum_enabled=true"],
        "tablespace": "standard_hdd",
    }

    diff = compare_table_attrs(ref_table, cmp_table)
    assert diff is not None
    assert diff["persistence"] == {"expected": "unlogged", "actual": "permanent"}
    assert diff["tablespace"] == {"expected": "fast_ssd", "actual": "standard_hdd"}
    assert "reloptions" in diff


def test_column_storage_and_compression_diff() -> None:
    """Detect attstorage (extended/external/main/plain) and attcompression (lz4/pglz) diffs."""
    ref_schema = {
        "columns": {
            "documents": [
                {
                    "column_name": "payload",
                    "data_type": "text",
                    "attstorage": "extended",
                    "attcompression": "lz4",
                }
            ]
        }
    }
    cmp_schema = {
        "columns": {
            "documents": [
                {
                    "column_name": "payload",
                    "data_type": "text",
                    "attstorage": "external",
                    "attcompression": "pglz",
                }
            ]
        }
    }

    diff = compare_columns(ref_schema, cmp_schema)
    assert "documents" in diff["mismatched"]
    doc_diff = next(
        item["payload"] for item in diff["mismatched"]["documents"] if "payload" in item
    )
    assert doc_diff["attstorage"] == {"expected": "extended", "actual": "external"}
    assert doc_diff["attcompression"] == {"expected": "lz4", "actual": "pglz"}


def test_column_ordinal_position_tracking() -> None:
    """Verify optional column ordinal position tracking flag."""
    ref_schema = {
        "columns": {
            "users": [
                {"column_name": "id", "data_type": "int", "ordinal_position": 1},
                {"column_name": "email", "data_type": "text", "ordinal_position": 2},
                {"column_name": "name", "data_type": "text", "ordinal_position": 3},
            ]
        }
    }
    cmp_schema = {
        "columns": {
            "users": [
                {"column_name": "id", "data_type": "int", "ordinal_position": 1},
                {"column_name": "name", "data_type": "text", "ordinal_position": 2},
                {"column_name": "email", "data_type": "text", "ordinal_position": 3},
            ]
        }
    }

    # Default: ordinal position is ignored
    diff_default = compare_snapshots(ref_schema, cmp_schema, track_ordinal_position=False)
    assert not has_drift(diff_default)

    # Enabled: differences in column ordinal positions are reported
    diff_tracked = compare_snapshots(ref_schema, cmp_schema, track_ordinal_position=True)
    assert has_drift(diff_tracked)
    assert "users" in diff_tracked["columns"]["mismatched"]
    email_diff = next(
        item["email"] for item in diff_tracked["columns"]["mismatched"]["users"] if "email" in item
    )
    assert email_diff["ordinal_position"] == {"expected": 2, "actual": 3}


def test_server_context_extraction_and_reporting() -> None:
    """Capture server_version, encoding, collations, and verify warning generation in reports."""
    ref_snap = {
        "snapshot_version": 1,
        "server_version": "16.3",
        "server_encoding": "UTF8",
        "lc_collate": "en_US.UTF-8",
        "lc_ctype": "en_US.UTF-8",
        "tables": {},
    }
    cmp_snap = {
        "snapshot_version": 1,
        "server_version": "15.7",
        "server_encoding": "SQL_ASCII",
        "lc_collate": "C",
        "lc_ctype": "C",
        "tables": {},
    }

    diff = compare_snapshots(ref_snap, cmp_snap)
    assert "server_context" in diff
    assert "server_version" in diff["server_context"]["mismatched"]
    assert "server_encoding" in diff["server_context"]["mismatched"]
    assert "lc_collate" in diff["server_context"]["mismatched"]
    assert "lc_ctype" in diff["server_context"]["mismatched"]

    report = build_report(
        reference="prod_db",
        compared="staging_db",
        schema="public",
        diff=diff,
    )

    assert len(report["warnings"]) >= 3
    assert any("server_version" in w for w in report["warnings"])
    assert any("server_encoding" in w for w in report["warnings"])

    txt = format_text_report(report)
    assert "Warnings:" in txt
    assert "[!] Server context mismatch on server_version" in txt
    assert "Drift detected: False" in txt
    assert "Environment warnings:" in txt
    assert "server_context" not in txt.split("Counts by section:")[-1]

    md = format_markdown_report(report)
    assert "### ⚠️ Warnings" in md
    assert "Server context mismatch on server_version" in md


def test_multi_schema_snapshot_options_and_qualification() -> None:
    """Verify multi-schema options and qualified identifiers across objects."""
    opts = SnapshotOptions(
        schema="public,analytics",
        schemas=("public", "analytics"),
        all_schemas=False,
    )
    assert opts.schemas == ("public", "analytics")

    ref_multi = {
        "snapshot_version": 1,
        "schema": "public,analytics",
        "schemas": ["public", "analytics"],
        "tables": {
            "public.users": {
                "table_name": "public.users",
                "schema_name": "public",
                "table_type": "table",
            },
            "analytics.events": {
                "table_name": "analytics.events",
                "schema_name": "analytics",
                "table_type": "table",
            },
        },
        "columns": {
            "public.users": [{"column_name": "id", "data_type": "uuid"}],
            "analytics.events": [{"column_name": "event_id", "data_type": "bigint"}],
        },
    }

    cmp_multi = {
        "snapshot_version": 1,
        "schema": "public,analytics",
        "schemas": ["public", "analytics"],
        "tables": {
            "public.users": {
                "table_name": "public.users",
                "schema_name": "public",
                "table_type": "table",
            },
            "analytics.events": {
                "table_name": "analytics.events",
                "schema_name": "analytics",
                "table_type": "partitioned_table",
            },
        },
        "columns": {
            "public.users": [{"column_name": "id", "data_type": "uuid"}],
            "analytics.events": [{"column_name": "event_id", "data_type": "bigint"}],
        },
    }

    diff = compare_snapshots(ref_multi, cmp_multi)
    assert has_drift(diff)
    assert "analytics.events" in diff["tables"]["mismatched"]


def test_filter_snapshot_tables() -> None:
    """Verify include/exclude table filtering in snapshots."""
    snapshot = {
        "tables": {
            "users": {"table_name": "users"},
            "orders": {"table_name": "orders"},
            "tmp_log": {"table_name": "tmp_log"},
        },
        "columns": {
            "users": [{"column_name": "id"}],
            "orders": [{"column_name": "id"}],
            "tmp_log": [{"column_name": "id"}],
        },
        "indexes": [
            {"table_name": "users", "index_name": "idx_users"},
            {"table_name": "tmp_log", "index_name": "idx_tmp"},
        ],
    }

    opts_exclude = SnapshotOptions(exclude_tables="^tmp_")
    filtered = filter_snapshot_tables(snapshot, opts_exclude)
    assert "tmp_log" not in filtered["tables"]
    assert "tmp_log" not in filtered["columns"]
    assert len(filtered["indexes"]) == 1
    assert filtered["indexes"][0]["index_name"] == "idx_users"

    opts_include = SnapshotOptions(include_tables="^users$")
    filtered_inc = filter_snapshot_tables(snapshot, opts_include)
    assert "users" in filtered_inc["tables"]
    assert "orders" not in filtered_inc["tables"]
    assert "tmp_log" not in filtered_inc["tables"]
