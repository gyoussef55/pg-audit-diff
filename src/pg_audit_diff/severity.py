"""Severity enumeration, default priority maps, and severity lookup helpers."""

from __future__ import annotations

from enum import Enum
from typing import Any

__all__ = [
    "DEFAULT_SECTION_SEVERITIES",
    "DEFAULT_SEVERITY_MAP",
    "Severity",
    "get_default_severity",
]


class Severity(str, Enum):
    """Drift severity classifications."""

    BLOCKING = "blocking"
    WARNING = "warning"
    INFO = "info"

    @classmethod
    def from_str(cls, value: str | Severity) -> Severity:
        """Parse string to Severity enum (case-insensitive)."""
        if isinstance(value, cls):
            return value
        try:
            return cls[value.lower()]
        except KeyError:
            try:
                return cls[value.upper()]
            except KeyError as exc:
                valid = ", ".join(s.value for s in cls)
                raise ValueError(f"Invalid severity: {value!r}. Must be one of: {valid}") from exc

    @property
    def level(self) -> int:
        """Integer priority level for comparison (higher = more critical)."""
        levels = {Severity.BLOCKING: 3, Severity.WARNING: 2, Severity.INFO: 1}
        return levels[self]

    def __str__(self) -> str:
        return self.value

    def __ge__(self, other: Any) -> bool:
        if isinstance(other, (Severity, str)):
            return self.level >= Severity.from_str(other).level
        return NotImplemented

    def __gt__(self, other: Any) -> bool:
        if isinstance(other, (Severity, str)):
            return self.level > Severity.from_str(other).level
        return NotImplemented

    def __le__(self, other: Any) -> bool:
        if isinstance(other, (Severity, str)):
            return self.level <= Severity.from_str(other).level
        return NotImplemented

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, (Severity, str)):
            return self.level < Severity.from_str(other).level
        return NotImplemented


DEFAULT_SECTION_SEVERITIES: dict[str, dict[str, Severity]] = {
    "schemas": {
        "missing": Severity.BLOCKING,
        "unexpected": Severity.WARNING,
        "mismatched": Severity.BLOCKING,
    },
    "tables": {
        "missing": Severity.BLOCKING,
        "unexpected": Severity.WARNING,
        "mismatched": Severity.BLOCKING,
    },
    "columns": {
        "missing": Severity.BLOCKING,
        "unexpected": Severity.WARNING,
        "mismatched": Severity.BLOCKING,
    },
    "primary_keys": {
        "missing": Severity.BLOCKING,
        "unexpected": Severity.WARNING,
        "mismatched": Severity.BLOCKING,
    },
    "foreign_keys": {
        "missing": Severity.BLOCKING,
        "unexpected": Severity.WARNING,
        "mismatched": Severity.BLOCKING,
    },
    "unique_constraints": {
        "missing": Severity.BLOCKING,
        "unexpected": Severity.WARNING,
        "mismatched": Severity.BLOCKING,
    },
    "check_constraints": {
        "missing": Severity.BLOCKING,
        "unexpected": Severity.WARNING,
        "mismatched": Severity.BLOCKING,
    },
    "indexes": {
        "missing": Severity.WARNING,
        "unexpected": Severity.INFO,
        "mismatched": Severity.WARNING,
        "name_only": Severity.INFO,
    },
    "exclusion_constraints": {
        "missing": Severity.BLOCKING,
        "unexpected": Severity.WARNING,
        "mismatched": Severity.BLOCKING,
    },
    "types": {
        "missing": Severity.BLOCKING,
        "unexpected": Severity.WARNING,
        "mismatched": Severity.BLOCKING,
    },
    "views": {
        "missing": Severity.BLOCKING,
        "unexpected": Severity.WARNING,
        "mismatched": Severity.BLOCKING,
    },
    "sequences": {
        "missing": Severity.BLOCKING,
        "unexpected": Severity.WARNING,
        "mismatched": Severity.WARNING,
    },
    "policies": {
        "missing": Severity.BLOCKING,
        "unexpected": Severity.WARNING,
        "mismatched": Severity.BLOCKING,
    },
    "triggers": {
        "missing": Severity.WARNING,
        "unexpected": Severity.WARNING,
        "mismatched": Severity.WARNING,
    },
    "functions": {
        "missing": Severity.BLOCKING,
        "unexpected": Severity.WARNING,
        "mismatched": Severity.BLOCKING,
    },
    "extensions": {
        "missing": Severity.WARNING,
        "unexpected": Severity.INFO,
        "mismatched": Severity.INFO,
    },
    "comments": {
        "missing": Severity.INFO,
        "unexpected": Severity.INFO,
        "mismatched": Severity.INFO,
    },
    "migrations": {
        "missing": Severity.BLOCKING,
        "unexpected": Severity.WARNING,
        "mismatched": Severity.BLOCKING,
    },
    "privileges": {
        "missing": Severity.BLOCKING,
        "unexpected": Severity.WARNING,
        "mismatched": Severity.BLOCKING,
    },
    "server_context": {
        "missing": Severity.INFO,
        "unexpected": Severity.INFO,
        "mismatched": Severity.WARNING,
    },
}

DEFAULT_SEVERITY_MAP: dict[str, Severity] = {
    "missing": Severity.BLOCKING,
    "unexpected": Severity.WARNING,
    "mismatched": Severity.BLOCKING,
    "name_only": Severity.INFO,
}


def get_default_severity(
    section: str,
    bucket: str,
    custom_overrides: dict[str, str | Severity] | None = None,
) -> Severity:
    """Determine default severity for a finding with optional overrides."""
    if custom_overrides:
        exact_key = f"{section}.{bucket}"
        if exact_key in custom_overrides:
            return Severity.from_str(custom_overrides[exact_key])
        if section in custom_overrides:
            val = custom_overrides[section]
            if isinstance(val, dict) and bucket in val:
                return Severity.from_str(val[bucket])
            if isinstance(val, (str, Severity)):
                return Severity.from_str(val)
        if bucket in custom_overrides:
            val = custom_overrides[bucket]
            if isinstance(val, (str, Severity)):
                return Severity.from_str(val)

    sec_map = DEFAULT_SECTION_SEVERITIES.get(section, {})
    if bucket in sec_map:
        return sec_map[bucket]
    return DEFAULT_SEVERITY_MAP.get(bucket, Severity.WARNING)
