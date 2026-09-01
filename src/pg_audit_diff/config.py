"""Configuration loading, connection profiles, ignore rules, and credential redaction."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from pg_audit_diff.policy import (
    IgnoreRule as IgnoreRule,
)
from pg_audit_diff.policy import (
    filter_baseline_drift as filter_baseline_drift,
)
from pg_audit_diff.policy import (
    filter_diff_by_ignores as filter_diff_by_ignores,
)
from pg_audit_diff.policy import (
    load_baseline as load_baseline,
)

__all__ = [
    "Config",
    "IgnoreRule",
    "apply_ignore_rules",
    "filter_baseline_drift",
    "filter_diff_by_ignores",
    "format_safe_error",
    "load_baseline",
    "load_config",
    "load_ignore_rules",
    "load_profiles",
    "load_role_mapping",
    "redact_dsn",
    "resolve_database_url",
    "subtract_baseline",
]


@dataclass(frozen=True)
class Config:
    """Loaded configuration containing connection profiles, ignore rules, and role mappings."""

    profiles: dict[str, str] = field(default_factory=dict)
    ignore_rules: list[IgnoreRule] = field(default_factory=list)
    role_mapping: dict[str, str] = field(default_factory=dict)


def redact_dsn(url: str | None) -> str:
    """Mask password credentials in database URLs, connection strings, or error text."""
    if not url:
        return ""

    result = str(url)

    # Mask URI password credentials: scheme://user:password@host
    result = re.sub(
        r"([a-zA-Z][a-zA-Z0-9+.-]*://[^:\s@/]+):([^@\s/]+)@",
        r"\1:***@",
        result,
    )
    # Mask URI password without username: scheme://:password@host
    result = re.sub(
        r"([a-zA-Z][a-zA-Z0-9+.-]*://):([^@\s/]+)@",
        r"\1:***@",
        result,
    )
    # Mask libpq-style key-value password assignments
    result = re.sub(
        r"""\b(password\s*=\s*)(?:[^\s'"]+|'[^']*'|"[^"]*")""",
        r"\1***",
        result,
        flags=re.IGNORECASE,
    )

    return result


def format_safe_error(exc: Exception | str) -> str:
    """Format an exception or message string with all credentials safely redacted."""
    msg = str(exc)
    return redact_dsn(msg)


def load_config(config_path: Path) -> Config:
    """Load configuration including profiles, ignore rules, and role mappings from YAML."""
    with open(config_path) as handle:
        data = yaml.safe_load(handle) or {}

    if not isinstance(data, dict):
        raise ValueError(f"Config file {config_path} must be a YAML mapping")

    profiles = _parse_profiles(data)
    ignore_rules = _parse_ignore_rules(
        data.get("ignore_rules") or data.get("ignore") or data.get("rules") or []
    )
    role_mapping = _parse_role_mapping(
        data.get("role_mapping") or data.get("role_map") or data.get("roles") or {}
    )
    return Config(profiles=profiles, ignore_rules=ignore_rules, role_mapping=role_mapping)


def load_profiles(config_path: Path) -> dict[str, str]:
    """Load named database URLs from a YAML file."""
    config = load_config(config_path)
    return config.profiles


def load_ignore_rules(config_path: Path) -> list[IgnoreRule]:
    """Load ignore rules from a YAML configuration file."""
    config = load_config(config_path)
    return config.ignore_rules


def load_role_mapping(config_path: Path) -> dict[str, str]:
    """Load role mapping dict from a YAML configuration file."""
    config = load_config(config_path)
    return config.role_mapping


_NON_PROFILE_KEYS = frozenset(
    {"profiles", "ignore_rules", "ignore", "rules", "role_mapping", "role_map", "roles"}
)


def _parse_profiles(data: dict[str, Any]) -> dict[str, str]:
    """Read connection profiles from an explicit ``profiles:`` block or the top level.

    Entries inside an explicit block are validated strictly so a malformed profile is a
    hard error. At the top level, unrecognized keys are skipped instead, so an unrelated
    setting alongside ``ignore_rules`` does not read as a broken profile.
    """
    explicit = "profiles" in data
    profiles_data = data.get("profiles") or {} if explicit else data
    if not isinstance(profiles_data, dict):
        raise ValueError("Config must contain a 'profiles' mapping of name -> url")

    result: dict[str, str] = {}
    for name, value in profiles_data.items():
        if not explicit and name in _NON_PROFILE_KEYS:
            continue
        if isinstance(value, str):
            result[str(name)] = value
        elif isinstance(value, dict) and "url" in value:
            result[str(name)] = str(value["url"])
        elif explicit:
            raise ValueError(f"Profile {name!r} must be a URL string or {{url: ...}}")
    return result


def _parse_role_mapping(raw: Any) -> dict[str, str]:
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("'role_mapping' must be a dictionary mapping ref_role -> cmp_role")
    return {str(k): str(v) for k, v in raw.items()}


def _validate_rule_pattern(pattern: str | None, field: str) -> str | None:
    """Compile a rule pattern up front so a typo fails config loading, not the comparison."""
    if pattern is None:
        return None
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(
            f"Invalid regular expression in ignore rule {field}: {pattern!r} ({exc})"
        ) from exc
    return pattern


def _parse_ignore_rules(raw_rules: Any) -> list[IgnoreRule]:
    if not isinstance(raw_rules, list):
        raise ValueError("'ignore_rules' must be a list of rule mappings")

    rules: list[IgnoreRule] = []
    for item in raw_rules:
        if isinstance(item, str):
            rules.append(
                IgnoreRule(section="*", name_pattern=_validate_rule_pattern(item, "name_pattern"))
            )
            continue
        if not isinstance(item, dict):
            raise ValueError(f"Each ignore rule must be a mapping, got {type(item).__name__}")

        section = str(item.get("section") or item.get("type") or "*")
        table_pattern = item.get("table_pattern")
        name_pattern = item.get("name_pattern") or item.get("pattern") or item.get("regex")
        reason = str(item.get("reason") or "")
        expires_at = item.get("expires_at") or item.get("expires")
        bucket = str(item["bucket"]) if item.get("bucket") else None

        rules.append(
            IgnoreRule(
                section=section,
                table_pattern=_validate_rule_pattern(
                    str(table_pattern) if table_pattern is not None else None, "table_pattern"
                ),
                name_pattern=_validate_rule_pattern(
                    str(name_pattern) if name_pattern is not None else None, "name_pattern"
                ),
                bucket=bucket,
                reason=reason,
                expires_at=str(expires_at) if expires_at is not None else None,
            )
        )
    return rules


def resolve_database_url(
    *,
    explicit_url: str | None,
    profile_name: str | None,
    env_var: str,
    profiles: dict[str, str] | None,
    label: str,
    profile_flag: str | None = None,
) -> str:
    """Resolve a connection URL from CLI flag, profile, or environment."""
    profile_opt = profile_flag or f"{label}-profile"
    if explicit_url:
        return explicit_url
    if profile_name:
        if not profiles:
            raise ValueError(f"--{profile_opt} requires --config with profiles")
        url = profiles.get(profile_name)
        if not url:
            raise ValueError(f"Unknown profile for {label}: {profile_name}")
        return url
    from_env = os.environ.get(env_var)
    if from_env:
        return from_env
    raise ValueError(
        f"Missing connection for {label}. Set {env_var}, pass --{label}-url, "
        f"or --{profile_opt} with --config."
    )


apply_ignore_rules = filter_diff_by_ignores
subtract_baseline = filter_baseline_drift
