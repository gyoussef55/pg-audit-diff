"""Unit tests for configuration loading, profiles, ignore rules, and credential redaction."""

from __future__ import annotations

from pathlib import Path

import pytest

from pg_audit_diff.config import (
    Config,
    format_safe_error,
    load_config,
    load_ignore_rules,
    load_profiles,
    redact_dsn,
    resolve_database_url,
)


def test_redact_dsn() -> None:
    # URL with username and password
    url1 = "postgresql://myuser:secret123@db.example.com:5432/myapp"
    assert redact_dsn(url1) == "postgresql://myuser:***@db.example.com:5432/myapp"

    # URL with special characters in password and query params
    url2 = "postgres://admin:p%40ss%3Aword@127.0.0.1:5433/test_db?sslmode=require"
    assert redact_dsn(url2) == "postgres://admin:***@127.0.0.1:5433/test_db?sslmode=require"

    # URL without password
    url3 = "postgresql://readonly_user@localhost/prod"
    assert redact_dsn(url3) == "postgresql://readonly_user@localhost/prod"

    # Key-value DSN
    dsn_kv = "host=localhost port=5432 user=pg password=mypassword dbname=demo"
    assert redact_dsn(dsn_kv) == "host=localhost port=5432 user=pg password=*** dbname=demo"

    # Quoted password in key-value
    dsn_kv_quoted = "host=db.internal user=root password='complex secret' dbname=app"
    assert redact_dsn(dsn_kv_quoted) == "host=db.internal user=root password=*** dbname=app"

    # Empty string
    assert redact_dsn("") == ""


def test_format_safe_error() -> None:
    raw_error = (
        "Database error: could not connect to server: "
        "postgresql://service_account:super_secret_token@10.0.1.5:5432/warehouse"
    )
    safe = format_safe_error(raw_error)
    assert "super_secret_token" not in safe
    assert "postgresql://service_account:***@10.0.1.5:5432/warehouse" in safe


def test_load_config_and_profiles(tmp_path: Path) -> None:
    config_file = tmp_path / "profiles.yaml"
    config_file.write_text(
        """
profiles:
  prod: postgresql://user:pass@prod-host:5432/db
  stage:
    url: postgresql://user:pass@stage-host:5432/db

ignore_rules:
  - section: tables
    table_pattern: "^temp_"
    reason: "Skip temp tables"
  - section: columns
    table_pattern: "^users$"
    name_pattern: "^debug_"
    reason: "Debug columns"
    expires_at: "2026-12-31"
"""
    )

    config = load_config(config_file)
    assert isinstance(config, Config)
    assert config.profiles["prod"] == "postgresql://user:pass@prod-host:5432/db"
    assert config.profiles["stage"] == "postgresql://user:pass@stage-host:5432/db"

    assert len(config.ignore_rules) == 2
    rule1 = config.ignore_rules[0]
    assert rule1.section == "tables"
    assert rule1.table_pattern == "^temp_"
    assert rule1.reason == "Skip temp tables"

    rule2 = config.ignore_rules[1]
    assert rule2.section == "columns"
    assert rule2.table_pattern == "^users$"
    assert rule2.name_pattern == "^debug_"
    assert rule2.expires_at == "2026-12-31"

    # load_profiles helper
    profiles = load_profiles(config_file)
    assert profiles == config.profiles

    # load_ignore_rules helper
    rules = load_ignore_rules(config_file)
    assert rules == config.ignore_rules


def test_resolve_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    # Explicit URL takes precedence
    assert (
        resolve_database_url(
            explicit_url="postgresql://explicit:5432/db",
            profile_name="prod",
            env_var="MY_DB_URL",
            profiles={"prod": "postgresql://profile:5432/db"},
            label="test",
        )
        == "postgresql://explicit:5432/db"
    )

    # Profile lookup
    assert (
        resolve_database_url(
            explicit_url=None,
            profile_name="prod",
            env_var="MY_DB_URL",
            profiles={"prod": "postgresql://profile:5432/db"},
            label="test",
        )
        == "postgresql://profile:5432/db"
    )

    # Missing profile raises
    with pytest.raises(ValueError, match="Unknown profile for test"):
        resolve_database_url(
            explicit_url=None,
            profile_name="missing",
            env_var="MY_DB_URL",
            profiles={"prod": "postgresql://profile:5432/db"},
            label="test",
        )

    # Env var lookup
    monkeypatch.setenv("MY_DB_URL", "postgresql://env:5432/db")
    assert (
        resolve_database_url(
            explicit_url=None,
            profile_name=None,
            env_var="MY_DB_URL",
            profiles=None,
            label="test",
        )
        == "postgresql://env:5432/db"
    )

    # Missing all raises
    monkeypatch.delenv("MY_DB_URL", raising=False)
    with pytest.raises(ValueError, match="Missing connection for test"):
        resolve_database_url(
            explicit_url=None,
            profile_name=None,
            env_var="MY_DB_URL",
            profiles=None,
            label="test",
        )

    # Custom profile flag name in error message
    with pytest.raises(ValueError, match="--profile with --config"):
        resolve_database_url(
            explicit_url=None,
            profile_name=None,
            env_var="DATABASE_URL",
            profiles=None,
            label="database",
            profile_flag="profile",
        )


def test_load_role_mapping(tmp_path: Path) -> None:
    config_file = tmp_path / "config_roles.yaml"
    config_file.write_text(
        """
role_mapping:
  prod_app: stage_app
  prod_admin: stage_admin
"""
    )
    config = load_config(config_file)
    assert config.role_mapping == {"prod_app": "stage_app", "prod_admin": "stage_admin"}
