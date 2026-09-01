"""Unit tests for policy evaluation: ignore rules, baseline filtering, and severity calculation."""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any

import pytest

from pg_audit_diff.policy import (
    IgnoreRule,
    Severity,
    apply_severity,
    calculate_severity,
    filter_baseline,
    filter_by_ignore_rules,
    filter_diff_by_ignores,
    get_default_severity,
    load_baseline,
    summarize_severities,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_severity_enum_and_comparisons() -> None:
    assert Severity.from_str("blocking") == Severity.BLOCKING
    assert Severity.from_str("BLOCKING") == Severity.BLOCKING
    assert Severity.from_str("warning") == Severity.WARNING
    assert Severity.from_str("info") == Severity.INFO

    with pytest.raises(ValueError, match="Invalid severity"):
        Severity.from_str("critical")

    assert Severity.BLOCKING > Severity.WARNING > Severity.INFO
    assert Severity.INFO < Severity.WARNING < Severity.BLOCKING
    assert Severity.BLOCKING >= Severity.BLOCKING
    assert Severity.WARNING >= "info"


def test_ignore_rule_matches_regex_pattern() -> None:
    """Ignore rules should filter matching items by name regex within or across sections."""
    diff: dict[str, Any] = {
        "tables": {
            "missing": {
                "backup_users_2026": {"table_name": "backup_users_2026"},
                "important_orders": {"table_name": "important_orders"},
            },
            "unexpected": {},
            "mismatched": {},
        },
        "columns": {
            "missing": {
                "users": ["temp_token", "active_status"],
            },
            "unexpected": {},
            "mismatched": {},
        },
    }

    rules = [
        IgnoreRule(section="tables", pattern=r"^backup_.*", reason="Temporary backup tables"),
        IgnoreRule(section="columns", pattern=r"^temp_.*", reason="Ephemeral columns"),
    ]

    filtered_diff, warnings = filter_by_ignore_rules(diff, rules)
    assert len(warnings) == 0
    assert "backup_users_2026" not in filtered_diff["tables"]["missing"]
    assert "important_orders" in filtered_diff["tables"]["missing"]
    assert "temp_token" not in filtered_diff["columns"]["missing"]["users"]
    assert "active_status" in filtered_diff["columns"]["missing"]["users"]


def test_ignore_rule_with_table_and_name_pattern() -> None:
    """Ignore rule with table and name pattern should only filter matches satisfying both."""
    diff: dict[str, Any] = {
        "columns": {
            "missing": {
                "users": ["debug_id", "email"],
                "accounts": ["debug_id", "balance"],
            },
            "unexpected": {},
            "mismatched": {},
        }
    }

    rule = IgnoreRule(
        section="columns",
        table_pattern=r"^users$",
        name_pattern=r"^debug_",
        reason="Only debug columns on users table",
    )

    filtered = filter_diff_by_ignores(diff, [rule])
    assert "debug_id" not in filtered["columns"]["missing"]["users"]
    assert "email" in filtered["columns"]["missing"]["users"]
    assert "debug_id" in filtered["columns"]["missing"]["accounts"]
    assert "balance" in filtered["columns"]["missing"]["accounts"]


def test_ignore_rule_wildcard_section() -> None:
    """Wildcard section '*' should match across any schema section."""
    diff: dict[str, Any] = {
        "tables": {
            "unexpected": {"legacy_audit_table": {"table_name": "legacy_audit_table"}},
            "missing": {},
            "mismatched": {},
        },
        "indexes": {
            "unexpected": {"idx_legacy_audit": {"index_name": "idx_legacy_audit"}},
            "missing": {},
            "mismatched": {},
            "name_only": {},
        },
    }

    rules = [
        IgnoreRule(section="*", pattern=r".*legacy_audit.*", reason="Ignore legacy audit objects")
    ]
    filtered_diff, warnings = filter_by_ignore_rules(diff, rules)
    assert len(warnings) == 0
    assert "legacy_audit_table" not in filtered_diff["tables"]["unexpected"]
    assert "idx_legacy_audit" not in filtered_diff["indexes"]["unexpected"]


def test_ignore_rule_expired_generates_warning() -> None:
    """Expired ignore rules must emit a warning and not filter drift after their expiry date."""
    diff: dict[str, Any] = {
        "tables": {
            "missing": {"archived_logs": {"table_name": "archived_logs"}},
            "unexpected": {},
            "mismatched": {},
        }
    }

    past_date = datetime.date(2025, 1, 1)
    future_date = datetime.date(2030, 1, 1)
    as_of_date = datetime.date(2026, 8, 31)

    expired_rule = IgnoreRule(
        section="tables",
        pattern=r"^archived_.*",
        reason="Muted during Q4 migration",
        expires_at=past_date,
    )
    active_rule = IgnoreRule(
        section="tables",
        pattern=r"^archived_.*",
        reason="Muted during Q4 migration",
        expires_at=future_date,
    )

    # 1. Expired rule: does not filter drift, emits warning
    filtered_expired, warnings_expired = filter_by_ignore_rules(
        diff, [expired_rule], as_of=as_of_date
    )
    assert len(warnings_expired) == 1
    assert "expired on 2025-01-01" in warnings_expired[0]
    assert "archived_logs" in filtered_expired["tables"]["missing"]

    # 2. Active rule: filters drift, no warnings
    filtered_active, warnings_active = filter_by_ignore_rules(diff, [active_rule], as_of=as_of_date)
    assert len(warnings_active) == 0
    assert "archived_logs" not in filtered_active["tables"]["missing"]


def test_load_baseline(tmp_path: Path) -> None:
    baseline_file = tmp_path / "baseline.json"
    content = {
        "version": 1,
        "diff": {
            "tables": {"missing": {"old_table": {}}, "unexpected": {}, "mismatched": {}},
        },
    }
    baseline_file.write_text(json.dumps(content))

    loaded = load_baseline(baseline_file)
    assert "tables" in loaded
    assert "old_table" in loaded["tables"]["missing"]

    # Invalid file raises ValueError
    invalid_file = tmp_path / "invalid.json"
    invalid_file.write_text("[]")
    with pytest.raises(ValueError, match="JSON object"):
        load_baseline(invalid_file)


def test_baseline_filtering_ignores_existing_drift_and_catches_new_drift() -> None:
    """Baseline filtering must subtract known existing drift and report newly added drift."""
    # Baseline accepted drift: missing 'old_table' and mismatched column 'amount'
    baseline_diff: dict[str, Any] = {
        "tables": {
            "missing": {"old_table": {"table_name": "old_table"}},
            "unexpected": {},
            "mismatched": {},
        },
        "columns": {
            "missing": {},
            "unexpected": {},
            "mismatched": {
                "orders": [
                    {
                        "amount": {
                            "data_type": {"expected": "numeric(10,2)", "actual": "numeric(19,4)"}
                        }
                    }
                ],
            },
        },
    }

    # Current diff: contains known drift PLUS newly added unauthorized table
    current_diff: dict[str, Any] = {
        "tables": {
            "missing": {
                "old_table": {"table_name": "old_table"},
                "new_unauthorized_table": {"table_name": "new_unauthorized_table"},
            },
            "unexpected": {},
            "mismatched": {},
        },
        "columns": {
            "missing": {},
            "unexpected": {},
            "mismatched": {
                "orders": [
                    {
                        "amount": {
                            "data_type": {"expected": "numeric(10,2)", "actual": "numeric(19,4)"}
                        }
                    },
                    {"user_id": {"data_type": {"expected": "uuid", "actual": "text"}}},
                ],
            },
        },
    }

    filtered_diff = filter_baseline(current_diff, baseline_diff)

    # Pre-existing drift in baseline should be removed
    assert "old_table" not in filtered_diff["tables"]["missing"]
    assert {
        "amount": {"data_type": {"expected": "numeric(10,2)", "actual": "numeric(19,4)"}}
    } not in filtered_diff["columns"]["mismatched"]["orders"]

    # New drift not in baseline must be preserved
    assert "new_unauthorized_table" in filtered_diff["tables"]["missing"]
    assert {"user_id": {"data_type": {"expected": "uuid", "actual": "text"}}} in filtered_diff[
        "columns"
    ]["mismatched"]["orders"]


def test_severity_calculation_levels_and_counts() -> None:
    """Severity calculation must classify findings by severity level and determine max severity."""
    clean_diff: dict[str, Any] = {
        "tables": {"missing": {}, "unexpected": {}, "mismatched": {}},
        "indexes": {"missing": {}, "unexpected": {}, "mismatched": {}, "name_only": {}},
    }
    clean_sev = calculate_severity(clean_diff)
    assert clean_sev["max_severity"] == "none"
    assert clean_sev["counts"]["blocking"] == 0
    assert clean_sev["counts"]["warning"] == 0
    assert clean_sev["counts"]["info"] == 0

    # Diff with index rename (INFO), missing index (WARNING), and missing table (BLOCKING)
    drift_diff: dict[str, Any] = {
        "tables": {
            "missing": {"critical_users": {"table_name": "critical_users"}},
            "unexpected": {},
            "mismatched": {},
        },
        "indexes": {
            "missing": {"idx_orders_created": {"index_name": "idx_orders_created"}},
            "unexpected": {},
            "mismatched": {},
            "name_only": {
                "idx_users_email": {
                    "expected": "idx_users_email",
                    "actual": "idx_users_email_renamed",
                }
            },
        },
    }

    drift_sev = calculate_severity(drift_diff)
    assert drift_sev["max_severity"] == Severity.BLOCKING.value
    assert drift_sev["counts"][Severity.BLOCKING.value] == 1  # missing table
    assert drift_sev["counts"][Severity.WARNING.value] == 1  # missing index
    assert drift_sev["counts"][Severity.INFO.value] == 1  # name_only index


def test_bookkeeping_buckets_are_not_counted_as_findings() -> None:
    """The indexes `duplicates` bucket is always populated and must not imply drift."""
    clean_diff: dict[str, Any] = {
        "indexes": {
            "missing": {},
            "unexpected": {},
            "mismatched": {},
            "name_only": {},
            "duplicates": {"reference": [], "compared": []},
        }
    }
    assert summarize_severities(clean_diff) == {"blocking": 0, "warning": 0, "info": 0}

    result = calculate_severity(clean_diff)
    assert result["has_drift"] is False
    assert result["max_severity"] == "none"
    assert result["findings"] == []


def test_server_context_is_not_counted_in_policy_severity() -> None:
    diff: dict[str, Any] = {
        "server_context": {
            "missing": {},
            "unexpected": {},
            "mismatched": {
                "server_version": {"expected": "16.3", "actual": "15.7"},
            },
        }
    }
    assert summarize_severities(diff) == {"blocking": 0, "warning": 0, "info": 0}
    result = calculate_severity(diff)
    assert result["has_drift"] is False
    assert result["findings"] == []


def test_renames_are_counted_but_are_not_drift() -> None:
    """name_only is reported at INFO, yet a rename alone must not count as drift."""
    rename_diff: dict[str, Any] = {
        "indexes": {
            "missing": {},
            "unexpected": {},
            "mismatched": {},
            "name_only": {"idx_users_email": {"expected_name": "a", "actual_name": "b"}},
            "duplicates": {"reference": [], "compared": []},
        }
    }
    result = calculate_severity(rename_diff)
    assert result["counts"][Severity.INFO.value] == 1
    assert result["has_drift"] is False


def test_expired_rule_warning_names_the_configured_pattern() -> None:
    """The warning must show the user's pattern, not the unused default '.*'."""
    rule = IgnoreRule(
        section="indexes", name_pattern="^idx_legacy_", expires_at="2020-01-01", reason="temp"
    )
    _, warnings = filter_by_ignore_rules({}, [rule])
    assert len(warnings) == 1
    assert "'^idx_legacy_'" in warnings[0]
    assert "'.*'" not in warnings[0]


def test_apply_severity_with_min_severity_filter() -> None:
    sample_diff: dict[str, Any] = {
        "tables": {
            "missing": {"users": {"table_name": "users"}},
            "unexpected": {},
            "mismatched": {},
        },
        "indexes": {
            "missing": {"idx_orders_created": {"index_name": "idx_orders_created"}},
            "unexpected": {},
            "mismatched": {},
        },
    }

    result = apply_severity(sample_diff, min_severity=Severity.BLOCKING)
    assert "users" in result["diff"]["tables"]["missing"]
    assert not result["diff"]["indexes"]["missing"]


def test_severity_calculation_with_custom_overrides() -> None:
    """Custom severity overrides should reclassify findings according to project policy."""
    diff: dict[str, Any] = {
        "indexes": {
            "missing": {"idx_orders_created": {"index_name": "idx_orders_created"}},
            "unexpected": {},
            "mismatched": {},
            "name_only": {},
        }
    }

    # By default, missing index is WARNING
    default_sev = calculate_severity(diff)
    assert default_sev["max_severity"] == Severity.WARNING.value

    # Override missing index to BLOCKING
    overrides = {"indexes": {"missing": Severity.BLOCKING}}
    custom_sev = calculate_severity(diff, overrides=overrides)
    assert custom_sev["max_severity"] == Severity.BLOCKING.value
    assert custom_sev["counts"][Severity.BLOCKING.value] == 1


def test_get_default_severity_lookup() -> None:
    """get_default_severity helper should return expected defaults for standard sections."""
    assert get_default_severity("tables", "missing") == Severity.BLOCKING
    assert get_default_severity("indexes", "name_only") == Severity.INFO
    assert get_default_severity("triggers", "missing") == Severity.WARNING
