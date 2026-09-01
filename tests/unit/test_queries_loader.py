"""Tests for SQL query loading."""

from __future__ import annotations

import pytest

from pg_audit_diff.queries_loader import load_migrations_query, load_query, validate_sql_identifier
from pg_audit_diff.snapshot import SNAPSHOT_SECTIONS


def test_load_query_tables() -> None:
    sql = load_query("tables")
    assert "%(schema)s" in sql
    assert "json_object_agg" in sql


def test_load_all_snapshot_sections() -> None:
    for section in SNAPSHOT_SECTIONS:
        sql = load_query(section)
        assert len(sql.strip()) > 0
        if section != "extensions":
            assert "%(schema)s" in sql
        assert "information_schema" not in sql.lower()


def test_migrations_query_renders_identifiers() -> None:
    sql = load_migrations_query("public", "migrations")
    assert "FROM public.migrations" in sql


def test_invalid_identifier_rejected() -> None:
    with pytest.raises(ValueError):
        validate_sql_identifier("public;drop", "schema")
