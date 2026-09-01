"""Unit tests for pluggable migration history adapters and diffing."""

from __future__ import annotations

from typing import Any

from pg_audit_diff.diff import compare_snapshots, has_drift
from pg_audit_diff.migrations_adapters import (
    FRAMEWORK_SPECS,
    compare_migration_records,
    detect_framework_from_data,
    detect_framework_from_db,
    extract_migrations,
)


def test_framework_specs_defined() -> None:
    expected_fws = {
        "typeorm",
        "flyway",
        "alembic",
        "liquibase",
        "golang-migrate",
        "django",
        "rails",
    }
    assert expected_fws <= set(FRAMEWORK_SPECS.keys())


def test_auto_detect_framework_from_data() -> None:
    # Flyway
    flyway_data = [{"installed_rank": 1, "version": "1.0", "success": True, "checksum": 123}]
    assert detect_framework_from_data(flyway_data) == "flyway"

    # Golang-migrate
    golang_data = [{"version": 20260801, "dirty": False}]
    assert detect_framework_from_data(golang_data) == "golang-migrate"

    # Alembic
    alembic_data = [{"version_num": "1a2b3c4d5e"}]
    assert detect_framework_from_data(alembic_data) == "alembic"

    # Liquibase
    liquibase_data = [{"id": "1", "author": "dev", "filename": "v1.sql", "md5sum": "9:abc"}]
    assert detect_framework_from_data(liquibase_data) == "liquibase"

    # Django
    django_data = [{"id": 1, "app": "auth", "name": "0001_initial", "applied": "2026-08-01"}]
    assert detect_framework_from_data(django_data) == "django"

    # TypeORM
    typeorm_data = [{"id": 1, "timestamp": 1754006400000, "name": "Init1754006400000"}]
    assert detect_framework_from_data(typeorm_data) == "typeorm"

    # Rails
    rails_data = [{"version": "20260801000000"}]
    assert detect_framework_from_data(rails_data) == "rails"


def test_typeorm_checksum_and_timestamp_diff() -> None:
    ref = {
        "migrations": {
            "framework": "typeorm",
            "records": [
                {"id": 1, "timestamp": 1000, "name": "Init1000"},
                {"id": 2, "timestamp": 2000, "name": "Users2000"},
            ],
        }
    }
    cmp_snap = {
        "migrations": {
            "framework": "typeorm",
            "records": [
                {"id": 1, "timestamp": 1000, "name": "Init1000"},
                {"id": 2, "timestamp": 9999, "name": "Users2000"},  # timestamp mismatch
            ],
        }
    }
    diff = compare_snapshots(ref, cmp_snap)
    assert has_drift(diff)
    assert "Users2000" in diff["migrations"]["mismatched"]
    assert diff["migrations"]["mismatched"]["Users2000"]["timestamp"]["expected"] == 2000
    assert diff["migrations"]["mismatched"]["Users2000"]["timestamp"]["actual"] == 9999


def test_flyway_checksum_mismatch_and_failure_state() -> None:
    ref = {
        "migrations": {
            "framework": "flyway",
            "records": [
                {
                    "installed_rank": 1,
                    "version": "1.0",
                    "description": "init",
                    "type": "SQL",
                    "script": "V1_0__init.sql",
                    "checksum": 11111,
                    "installed_by": "postgres",
                    "installed_on": "2026-08-01 10:00:00",
                    "execution_time": 10,
                    "success": True,
                },
                {
                    "installed_rank": 2,
                    "version": "1.1",
                    "description": "add_users",
                    "type": "SQL",
                    "script": "V1_1__add_users.sql",
                    "checksum": 22222,
                    "installed_by": "postgres",
                    "installed_on": "2026-08-01 11:00:00",
                    "execution_time": 20,
                    "success": True,
                },
            ],
        }
    }
    cmp_snap = {
        "migrations": {
            "framework": "flyway",
            "records": [
                {
                    "installed_rank": 1,
                    "version": "1.0",
                    "description": "init",
                    "type": "SQL",
                    "script": "V1_0__init.sql",
                    "checksum": 99999,  # Checksum mismatch
                    "installed_by": "postgres",
                    "installed_on": "2026-08-01 10:00:00",
                    "execution_time": 10,
                    "success": True,
                },
                {
                    "installed_rank": 2,
                    "version": "1.1",
                    "description": "add_users",
                    "type": "SQL",
                    "script": "V1_1__add_users.sql",
                    "checksum": 22222,
                    "installed_by": "postgres",
                    "installed_on": "2026-08-01 11:00:00",
                    "execution_time": 20,
                    "success": False,  # Failure flag!
                },
            ],
        }
    }
    diff = compare_snapshots(ref, cmp_snap)
    assert has_drift(diff)
    assert "1.0" in diff["migrations"]["mismatched"]
    assert diff["migrations"]["mismatched"]["1.0"]["checksum"]["expected"] == 11111
    assert diff["migrations"]["mismatched"]["1.0"]["checksum"]["actual"] == 99999

    assert "1.1" in diff["migrations"]["mismatched"]
    assert diff["migrations"]["mismatched"]["1.1"]["success"]["actual"] is False


def test_golang_migrate_dirty_failure_flag() -> None:
    ref = {
        "migrations": {
            "framework": "golang-migrate",
            "records": [
                {"version": 1, "dirty": False},
                {"version": 2, "dirty": False},
            ],
        }
    }
    cmp_snap = {
        "migrations": {
            "framework": "golang-migrate",
            "records": [
                {"version": 1, "dirty": False},
                {"version": 2, "dirty": True},  # Dirty state
            ],
        }
    }
    diff = compare_snapshots(ref, cmp_snap)
    assert has_drift(diff)
    assert "2" in diff["migrations"]["mismatched"]
    assert diff["migrations"]["mismatched"]["2"]["dirty"]["actual"] is True


def test_liquibase_md5sum_and_failure_state() -> None:
    ref = {
        "migrations": {
            "framework": "liquibase",
            "records": [
                {
                    "id": "1",
                    "author": "alice",
                    "filename": "changelog.xml",
                    "orderexecuted": 1,
                    "exectype": "EXECUTED",
                    "md5sum": "8:abc123",
                },
                {
                    "id": "2",
                    "author": "bob",
                    "filename": "changelog.xml",
                    "orderexecuted": 2,
                    "exectype": "EXECUTED",
                    "md5sum": "8:def456",
                },
            ],
        }
    }
    cmp_snap = {
        "migrations": {
            "framework": "liquibase",
            "records": [
                {
                    "id": "1",
                    "author": "alice",
                    "filename": "changelog.xml",
                    "orderexecuted": 1,
                    "exectype": "EXECUTED",
                    "md5sum": "8:modified",  # md5sum mismatch
                },
                {
                    "id": "2",
                    "author": "bob",
                    "filename": "changelog.xml",
                    "orderexecuted": 2,
                    "exectype": "FAILED",  # execution failure
                    "md5sum": "8:def456",
                },
            ],
        }
    }
    diff = compare_snapshots(ref, cmp_snap)
    assert has_drift(diff)
    assert (
        "1" in diff["migrations"]["mismatched"]
        or "1:alice:changelog.xml" in diff["migrations"]["mismatched"]
    )
    mismatch_1 = diff["migrations"]["mismatched"].get("1") or diff["migrations"]["mismatched"].get(
        "1:alice:changelog.xml"
    )
    assert mismatch_1 and mismatch_1["md5sum"]["actual"] == "8:modified"
    assert (
        "2" in diff["migrations"]["mismatched"]
        or "2:bob:changelog.xml" in diff["migrations"]["mismatched"]
    )
    mismatch_2 = diff["migrations"]["mismatched"].get("2") or diff["migrations"]["mismatched"].get(
        "2:bob:changelog.xml"
    )
    assert mismatch_2 and mismatch_2["exectype"]["actual"] == "FAILED"


def test_django_migrations_missing_and_unexpected() -> None:
    ref = {
        "migrations": {
            "framework": "django",
            "records": [
                {"id": 1, "app": "users", "name": "0001_initial", "applied": "2026-08-01"},
                {"id": 2, "app": "users", "name": "0002_add_roles", "applied": "2026-08-02"},
            ],
        }
    }
    cmp_snap = {
        "migrations": {
            "framework": "django",
            "records": [
                {"id": 1, "app": "users", "name": "0001_initial", "applied": "2026-08-01"},
                {"id": 3, "app": "billing", "name": "0001_initial", "applied": "2026-08-03"},
            ],
        }
    }
    diff = compare_snapshots(ref, cmp_snap)
    assert has_drift(diff)
    assert "users.0002_add_roles" in diff["migrations"]["missing"]
    assert "billing.0001_initial" in diff["migrations"]["unexpected"]


def test_rails_migrations_version_diff() -> None:
    ref = {
        "migrations": {
            "framework": "rails",
            "records": [
                {"version": "20260801000000"},
                {"version": "20260802000000"},
            ],
        }
    }
    cmp_snap = {
        "migrations": {
            "framework": "rails",
            "records": [
                {"version": "20260801000000"},
            ],
        }
    }
    diff = compare_snapshots(ref, cmp_snap)
    assert has_drift(diff)
    assert "20260802000000" in diff["migrations"]["missing"]


def test_alembic_single_head_version() -> None:
    ref = {
        "migrations": {
            "framework": "alembic",
            "records": [{"version_num": "head_rev_1"}],
        }
    }
    cmp_snap = {
        "migrations": {
            "framework": "alembic",
            "records": [{"version_num": "head_rev_2"}],
        }
    }
    diff = compare_snapshots(ref, cmp_snap)
    assert has_drift(diff)
    assert "head_rev_1" in diff["migrations"]["missing"]
    assert "head_rev_2" in diff["migrations"]["unexpected"]


def test_out_of_order_execution_detected() -> None:
    ref = {
        "migrations": {
            "framework": "typeorm",
            "records": [
                {"id": 1, "timestamp": 100, "name": "MigA"},
                {"id": 2, "timestamp": 200, "name": "MigB"},
                {"id": 3, "timestamp": 300, "name": "MigC"},
            ],
        }
    }
    # In compared, MigB was executed before MigA
    cmp_snap = {
        "migrations": {
            "framework": "typeorm",
            "records": [
                {"id": 2, "timestamp": 200, "name": "MigB"},
                {"id": 1, "timestamp": 100, "name": "MigA"},
                {"id": 3, "timestamp": 300, "name": "MigC"},
            ],
        }
    }
    diff = compare_snapshots(ref, cmp_snap)
    assert has_drift(diff)
    assert "MigB" in diff["migrations"]["mismatched"] or "MigA" in diff["migrations"]["mismatched"]


def test_migration_diff_idempotence_and_symmetry() -> None:
    migs_a = {
        "framework": "flyway",
        "records": [
            {
                "installed_rank": 1,
                "version": "1.0",
                "description": "init",
                "type": "SQL",
                "script": "V1_0__init.sql",
                "checksum": 123,
                "installed_by": "admin",
                "installed_on": "2026-08-01",
                "execution_time": 10,
                "success": True,
            },
            {
                "installed_rank": 2,
                "version": "2.0",
                "description": "orders",
                "type": "SQL",
                "script": "V2_0__orders.sql",
                "checksum": 456,
                "installed_by": "admin",
                "installed_on": "2026-08-02",
                "execution_time": 15,
                "success": True,
            },
        ],
    }
    migs_b = {
        "framework": "flyway",
        "records": [
            {
                "installed_rank": 1,
                "version": "1.0",
                "description": "init",
                "type": "SQL",
                "script": "V1_0__init.sql",
                "checksum": 123,
                "installed_by": "admin",
                "installed_on": "2026-08-01",
                "execution_time": 10,
                "success": True,
            },
            {
                "installed_rank": 3,
                "version": "3.0",
                "description": "billing",
                "type": "SQL",
                "script": "V3_0__billing.sql",
                "checksum": 789,
                "installed_by": "admin",
                "installed_on": "2026-08-03",
                "execution_time": 20,
                "success": True,
            },
        ],
    }

    # Idempotence
    diff_self = compare_migration_records(migs_a, migs_a)
    assert not diff_self["missing"]
    assert not diff_self["unexpected"]
    assert not diff_self["mismatched"]

    # Symmetry
    diff_ab = compare_migration_records(migs_a, migs_b)
    diff_ba = compare_migration_records(migs_b, migs_a)

    assert len(diff_ab["missing"]) == len(diff_ba["unexpected"])
    assert len(diff_ab["unexpected"]) == len(diff_ba["missing"])
    assert "2.0" in diff_ab["missing"]
    assert "2.0" in diff_ba["unexpected"]
    assert "3.0" in diff_ab["unexpected"]
    assert "3.0" in diff_ba["missing"]


class _DummyCursor:
    def __init__(self, row: dict[str, Any] | None) -> None:
        self._row = row

    def fetchone(self) -> dict[str, Any] | None:
        return self._row


class _DummyConn:
    def __init__(self, tables: set[str], has_dirty: bool = False) -> None:
        self.tables = tables
        self.has_dirty = has_dirty

    def execute(self, query: str, params: Any = None) -> _DummyCursor:
        if "to_regclass" in query and params:
            tbl_qualified = params[0]
            tbl = tbl_qualified.split(".")[-1]
            return _DummyCursor({"present": tbl in self.tables})
        if "has_dirty" in query:
            return _DummyCursor({"has_dirty": self.has_dirty})
        return _DummyCursor({"result": [{"id": 1, "name": "Dummy"}]})


def test_detect_framework_from_db() -> None:
    # Flyway
    conn_flyway = _DummyConn({"flyway_schema_history"})
    assert detect_framework_from_db(conn_flyway, "public") == ("flyway", "flyway_schema_history")  # type: ignore[arg-type]

    # Alembic
    conn_alembic = _DummyConn({"alembic_version"})
    assert detect_framework_from_db(conn_alembic, "public") == ("alembic", "alembic_version")  # type: ignore[arg-type]

    # Liquibase
    conn_liquibase = _DummyConn({"databasechangelog"})
    assert detect_framework_from_db(conn_liquibase, "public") == ("liquibase", "databasechangelog")  # type: ignore[arg-type]

    # Golang-migrate vs Rails on schema_migrations
    conn_golang = _DummyConn({"schema_migrations"}, has_dirty=True)
    expected_gm: tuple[str, str] = ("golang-migrate", "schema_migrations")
    assert detect_framework_from_db(conn_golang, "public") == expected_gm  # type: ignore[arg-type]

    conn_rails = _DummyConn({"schema_migrations"}, has_dirty=False)
    expected_rails: tuple[str, str] = ("rails", "schema_migrations")
    assert detect_framework_from_db(conn_rails, "public") == expected_rails  # type: ignore[arg-type]

    # TypeORM
    conn_typeorm = _DummyConn({"migrations"})
    expected_to: tuple[str, str] = ("typeorm", "migrations")
    assert detect_framework_from_db(conn_typeorm, "public") == expected_to  # type: ignore[arg-type]


def test_extract_migrations_with_explicit_framework() -> None:
    conn = _DummyConn({"my_custom_migrations"})
    result = extract_migrations(
        conn,  # type: ignore[arg-type]
        "public",
        framework="typeorm",
        table_name="my_custom_migrations",
    )
    assert result["framework"] == "typeorm"
    assert result["table"] == "my_custom_migrations"
    assert len(result["records"]) == 1


def test_explicit_framework_falls_back_to_its_own_default_table() -> None:
    """Without a table override, a named framework must use its own default table.

    Passing a table name here previously shadowed the default and made this return {},
    which reads as "migration history agrees" and hides drift.
    """
    conn = _DummyConn({"flyway_schema_history"})
    result = extract_migrations(conn, "public", framework="flyway")  # type: ignore[arg-type]
    assert result["table"] == "flyway_schema_history"
    assert result["records"]
