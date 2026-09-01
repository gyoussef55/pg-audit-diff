"""Tests for schema-set comparison and optional schema-name normalization."""

from __future__ import annotations

from pg_audit_diff.diff import compare_snapshots, has_drift
from pg_audit_diff.schema_identity import (
    SCHEMA_PLACEHOLDER,
    compare_schema_sets,
    normalize_schema_identity,
    should_normalize_pair,
    snapshot_schemas,
)


def _snapshot(schema: str) -> dict[str, object]:
    """Build a snapshot whose catalog text embeds its own schema name, as Postgres renders it."""
    return {
        "snapshot_version": 1,
        "schema": schema,
        "schemas": [schema],
        "tables": {"users": {"schema_name": schema, "table_name": "users"}},
        "columns": {
            "users": [
                {
                    "column_name": "role",
                    "data_type": f"{schema}.user_role",
                    "column_default": f"'member'::{schema}.user_role",
                },
                {
                    "column_name": "id",
                    "data_type": "bigint",
                    "column_default": f"nextval('{schema}.users_id_seq'::regclass)",
                },
            ]
        },
        "views": {
            "active_users": {
                "view_name": "active_users",
                "definition": f" SELECT id FROM {schema}.users WHERE is_active;",
            }
        },
        "fks": [
            {
                "table_name": "users",
                "columns": ["dept_id"],
                "referenced_schema": schema,
                "referenced_table": "departments",
                "referenced_columns": ["id"],
            }
        ],
    }


def test_different_single_schema_names_report_drift_by_default() -> None:
    """Without opt-in normalization, app_prod vs app_staging is schema drift."""
    diff = compare_snapshots(_snapshot("app_prod"), _snapshot("app_staging"))

    assert "app_prod" in diff["schemas"]["missing"]
    assert "app_staging" in diff["schemas"]["unexpected"]
    assert has_drift(diff)


def test_opt_in_normalization_for_single_schema_rename() -> None:
    """normalize_schema_names=True enables comparing differently named single schemas."""
    diff = compare_snapshots(
        _snapshot("app_prod"),
        _snapshot("app_staging"),
        normalize_schema_names=True,
    )
    assert not has_drift(diff), f"schema rename reported as drift: {diff}"


def test_real_drift_survives_opt_in_normalization() -> None:
    reference = _snapshot("app_prod")
    compared = _snapshot("app_staging")
    compared["views"] = {
        "active_users": {
            "view_name": "active_users",
            "definition": " SELECT id FROM app_staging.users;",
        }
    }

    diff = compare_snapshots(reference, compared, normalize_schema_names=True)

    assert "active_users" in diff["views"]["mismatched"]


def test_reference_to_a_foreign_schema_is_not_rewritten() -> None:
    snapshot = _snapshot("app_prod")
    snapshot["fks"] = [
        {
            "table_name": "users",
            "columns": ["country_id"],
            "referenced_schema": "shared_lookup",
            "referenced_table": "countries",
            "referenced_columns": ["id"],
        }
    ]

    normalized = normalize_schema_identity(snapshot)

    assert normalized["fks"][0]["referenced_schema"] == "shared_lookup"


def test_own_schema_name_is_replaced_in_qualified_text() -> None:
    normalized = normalize_schema_identity(_snapshot("app_prod"))

    columns = normalized["columns"]["users"]
    assert columns[0]["data_type"] == f"{SCHEMA_PLACEHOLDER}.user_role"
    assert columns[1]["column_default"] == f"nextval('{SCHEMA_PLACEHOLDER}.users_id_seq'::regclass)"
    assert normalized["fks"][0]["referenced_schema"] == SCHEMA_PLACEHOLDER


def test_snapshot_provenance_fields_are_preserved() -> None:
    normalized = normalize_schema_identity(_snapshot("app_prod"))

    assert normalized["schema"] == "app_prod"
    assert normalized["schemas"] == ["app_prod"]


def test_longer_schema_name_is_not_partially_matched_by_a_shorter_one() -> None:
    snapshot = _snapshot("app")
    snapshot["schemas"] = ["app", "app_archive"]
    snapshot["views"] = {
        "v": {"definition": "SELECT * FROM app_archive.orders JOIN app.users USING (id)"}
    }

    normalized = normalize_schema_identity(snapshot)

    definition = normalized["views"]["v"]["definition"]
    assert definition == (
        f"SELECT * FROM {SCHEMA_PLACEHOLDER}.orders JOIN {SCHEMA_PLACEHOLDER}.users USING (id)"
    )


def test_table_named_like_the_schema_is_not_rewritten() -> None:
    snapshot = _snapshot("audit")
    snapshot["tables"] = {"audit": {"table_name": "audit", "schema_name": "audit"}}

    normalized = normalize_schema_identity(snapshot)

    assert normalized["tables"]["audit"]["table_name"] == "audit"


def test_should_normalize_pair_only_for_single_schema_rename() -> None:
    same = _snapshot("public")
    assert not should_normalize_pair(same, _snapshot("public"))
    assert should_normalize_pair(same, _snapshot("other"))

    multi_ref = _snapshot("public")
    multi_ref["schemas"] = ["public", "billing"]
    assert not should_normalize_pair(multi_ref, _snapshot("public"))


def test_multi_schema_set_difference_is_reported_as_drift() -> None:
    reference = _snapshot("public")
    reference["schemas"] = ["public", "billing"]
    reference["schema"] = "public"

    compared = _snapshot("public")
    compared["schemas"] = ["public"]

    diff = compare_snapshots(reference, compared)

    assert "billing" in diff["schemas"]["missing"]
    assert has_drift(diff)


def test_multi_schema_set_difference_is_not_normalized_away() -> None:
    reference = _snapshot("billing")
    reference["schemas"] = ["public", "billing"]
    reference["schema"] = "public"
    reference["fks"] = [
        {
            "table_name": "users",
            "columns": ["dept_id"],
            "referenced_schema": "billing",
            "referenced_table": "departments",
            "referenced_columns": ["id"],
        }
    ]

    compared = _snapshot("public")
    compared["schemas"] = ["public", "analytics"]
    compared["schema"] = "public"
    compared["fks"] = [
        {
            "table_name": "users",
            "columns": ["dept_id"],
            "referenced_schema": "analytics",
            "referenced_table": "departments",
            "referenced_columns": ["id"],
        }
    ]

    diff = compare_snapshots(reference, compared)

    assert "billing" in diff["schemas"]["missing"]
    assert "analytics" in diff["schemas"]["unexpected"]
    assert has_drift(diff)
    fk = diff["foreign_keys"]
    assert fk["missing"] or fk["unexpected"] or fk["mismatched"]


def test_compare_schema_sets_unit() -> None:
    ref = {"schemas": ["public", "billing"]}
    cmp = {"schemas": ["public", "analytics"]}
    result = compare_schema_sets(ref, cmp)

    assert result["missing"] == ["billing"]
    assert result["unexpected"] == ["analytics"]


def test_snapshot_schemas_falls_back_to_the_single_schema_field() -> None:
    assert snapshot_schemas({"schema": "reporting"}) == ("reporting",)
    assert snapshot_schemas({"schemas": ["a", "b"]}) == ("a", "b")
    assert snapshot_schemas({}) == ()
