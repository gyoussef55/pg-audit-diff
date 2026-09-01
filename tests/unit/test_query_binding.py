"""Verify every catalog query can bind the parameters the snapshot builder supplies.

These tests exist because a query and its caller can drift apart silently: the query
gets a new named placeholder, the snapshot builder never supplies it, and every unit
test still passes because none of them execute real SQL. The failure only appears
against a live server, where it takes down the whole snapshot.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from psycopg._queries import PostgresQuery
from psycopg.adapt import Transformer

from pg_audit_diff.queries_loader import load_migrations_query, load_query
from pg_audit_diff.snapshot import (
    OPTIONAL_SECTIONS,
    SNAPSHOT_SECTIONS,
    SnapshotOptions,
    build_snapshot_params,
    resolve_schemas,
)

QUERY_DIR = Path(__file__).parents[2] / "src" / "pg_audit_diff" / "queries"


def _bind(sql: str, params: dict[str, object]) -> None:
    """Resolve named placeholders exactly as psycopg does before sending to the server."""
    PostgresQuery(Transformer()).convert(sql.encode(), params)


@pytest.mark.parametrize("section", [*SNAPSHOT_SECTIONS, *OPTIONAL_SECTIONS])
def test_every_section_query_binds_single_schema_params(section: str) -> None:
    params = build_snapshot_params(("public",))
    _bind(load_query(section), params)


@pytest.mark.parametrize("section", [*SNAPSHOT_SECTIONS, *OPTIONAL_SECTIONS])
def test_every_section_query_binds_multi_schema_params(section: str) -> None:
    params = build_snapshot_params(("public", "analytics"))
    _bind(load_query(section), params)


def test_no_query_file_is_left_out_of_the_binding_check() -> None:
    """A new query file must be registered in a snapshot section, or it is never tested."""
    on_disk = {p.stem for p in QUERY_DIR.glob("*.sql")}
    registered = {*SNAPSHOT_SECTIONS, *OPTIONAL_SECTIONS, "migrations"}
    assert on_disk == registered, (
        f"unregistered query files: {sorted(on_disk - registered)}; "
        f"registered but missing files: {sorted(registered - on_disk)}"
    )


def test_migrations_query_binds_without_named_params() -> None:
    _bind(load_migrations_query("public", "migrations"), {})


def test_snapshot_params_always_include_both_placeholders() -> None:
    params = build_snapshot_params(("reporting",))
    assert params["schema"] == "reporting"
    assert params["schemas"] == ["reporting"]


def test_resolve_schemas_prefers_explicit_list_over_single_schema() -> None:
    opts = SnapshotOptions(schema="public", schemas=("public", "analytics"))
    conn: Any = _NoQueryConnection()
    assert resolve_schemas(conn, opts) == ("public", "analytics")


def test_resolve_schemas_expands_all_schemas_from_catalog() -> None:
    opts = SnapshotOptions(all_schemas=True)
    conn: Any = _CatalogConnection()
    assert resolve_schemas(conn, opts) == ("analytics", "public")


class _NoQueryConnection:
    """Connection that fails the test if the catalog is queried unnecessarily."""

    def execute(self, query: str, params: object = None) -> object:
        raise AssertionError(f"unexpected catalog query: {query}")


class _SchemaListCursor:
    def fetchall(self) -> list[dict[str, str]]:
        return [{"nspname": "analytics"}, {"nspname": "public"}]


class _CatalogConnection:
    def execute(self, query: str, params: object = None) -> _SchemaListCursor:
        assert "pg_namespace" in query
        return _SchemaListCursor()


def test_privilege_capture_refuses_multi_schema_rather_than_partially_answering() -> None:
    """privileges.sql reads one schema; a partial capture would read as 'no drift'."""
    from pg_audit_diff.snapshot import build_schema_snapshot

    opts = SnapshotOptions(
        schemas=("public", "analytics"),
        include_privileges=True,
        include_migrations=False,
    )
    conn: Any = _TransactionalConnection()

    with pytest.raises(ValueError, match="one schema at a time"):
        build_schema_snapshot(conn, options=opts)


class _TransactionalConnection:
    """Minimal connection supporting the snapshot transaction and context query."""

    @contextmanager
    def transaction(self) -> Iterator[_TransactionalConnection]:
        yield self

    def execute(self, query: str, params: object = None) -> _ContextCursor:
        return _ContextCursor()


class _ContextCursor:
    def fetchone(self) -> dict[str, str]:
        return {"server_version": "17.0"}

    def fetchall(self) -> list[dict[str, str]]:
        return []
