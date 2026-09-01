"""Policy engine, ignore rules, and baseline drift filtering."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

from pg_audit_diff.severity import (
    DEFAULT_SECTION_SEVERITIES,
    DEFAULT_SEVERITY_MAP,
    Severity,
    get_default_severity,
)

logger = logging.getLogger(__name__)

NON_DRIFT_SECTIONS: frozenset[str] = frozenset({"server_context"})

DRIFT_BUCKETS: tuple[str, ...] = ("missing", "unexpected", "mismatched")
SEVERITY_BUCKETS: tuple[str, ...] = (*DRIFT_BUCKETS, "name_only")

__all__ = [
    "DEFAULT_SECTION_SEVERITIES",
    "DEFAULT_SEVERITY_MAP",
    "DRIFT_BUCKETS",
    "SEVERITY_BUCKETS",
    "IgnoreRule",
    "Severity",
    "apply_severity",
    "calculate_severity",
    "filter_baseline",
    "filter_baseline_drift",
    "filter_by_ignore_rules",
    "filter_diff_by_ignores",
    "get_default_severity",
    "load_baseline",
    "summarize_severities",
]


@dataclass(frozen=True)
class IgnoreRule:
    """Rule defining schema drift items to ignore."""

    section: str = "*"
    table_pattern: str | None = None
    name_pattern: str | None = None
    pattern: str = ".*"
    bucket: str | None = None
    reason: str = ""
    expires_at: str | date | datetime | None = None
    expires: str | None = None

    @property
    def described_pattern(self) -> str:
        """The pattern a user actually wrote, for error and warning messages."""
        if self.pattern != ".*":
            return self.pattern
        return self.name_pattern or self.table_pattern or self.pattern

    def is_expired(self, as_of: date | datetime | None = None) -> bool:
        """Check if rule is expired as of a given date (defaults to today)."""
        exp_val = self.expires_at or self.expires
        if exp_val is None:
            return False

        ref: date = as_of.date() if isinstance(as_of, datetime) else (as_of or date.today())
        try:
            if isinstance(exp_val, str):
                exp_date = date.fromisoformat(exp_val.split("T")[0])
            elif isinstance(exp_val, datetime):
                exp_date = exp_val.date()
            elif isinstance(exp_val, date):
                exp_date = exp_val
            else:
                return False
            expired = exp_date < ref
            if expired:
                logger.warning(
                    "Ignore rule for section %r pattern=%r expired on %s; rule is ignored.",
                    self.section,
                    self.described_pattern,
                    exp_val,
                )
            return expired
        except (ValueError, TypeError) as exc:
            logger.warning("Invalid expiry %r in ignore rule: %s", exp_val, exc)
            return False

    def matches(
        self,
        section: str,
        item_name: str | None = None,
        table_name: str | None = None,
        object_name: str | None = None,
        bucket: str | None = None,
    ) -> bool:
        """Check if a diff entry matches this ignore rule."""
        norm_rule_sec = _canonical_section_name(self.section)
        norm_item_sec = _canonical_section_name(section)
        if norm_rule_sec != "*" and norm_rule_sec != norm_item_sec:
            return False

        if self.bucket is not None and bucket is not None and self.bucket != bucket:
            return False

        if self.table_pattern is not None and (
            table_name is None or not re.search(self.table_pattern, table_name)
        ):
            return False

        if self.name_pattern is not None:
            target = object_name if object_name is not None else item_name
            if target is None or not re.search(self.name_pattern, target):
                return False

        eff_pattern = (
            self.pattern
            if self.pattern != ".*"
            else (self.name_pattern or self.table_pattern or ".*")
        )
        if eff_pattern != ".*":
            cands = [c for c in (item_name, object_name, table_name) if c]
            if table_name and object_name and table_name != object_name:
                cands.append(f"{table_name}.{object_name}")
            if not cands or not any(re.search(eff_pattern, c) for c in cands):
                return False

        return True


def _canonical_section_name(section: str) -> str:
    sec = section.strip().lower()
    mapping = {
        "pks": "primary_keys",
        "ucs": "unique_constraints",
        "fks": "foreign_keys",
        "constraints": "check_constraints",
        "privilege": "privileges",
    }
    return mapping.get(sec, sec)


def _extract_item_names(value: Any) -> list[str]:
    """Extract object names from a diff entry for pattern matching."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        names: list[str] = []
        for key in (
            "table_name",
            "column_name",
            "index_name",
            "constraint_name",
            "view_name",
            "sequence_name",
            "policy_name",
            "trigger_name",
            "trigger_key",
            "function_name",
            "identity",
            "name",
            "type_name",
            "extension_name",
            "object_name",
        ):
            if value.get(key):
                names.append(str(value[key]))
        if not names:
            names.extend(str(k) for k in value)
        return names
    return [str(value)]


def filter_by_ignore_rules(
    diff: dict[str, Any],
    rules: list[IgnoreRule],
    as_of: date | datetime | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Filter out diff entries matching active ignore rules and return expired warnings."""
    warnings: list[str] = []
    active_rules: list[IgnoreRule] = []

    for rule in rules:
        if rule.is_expired(as_of=as_of):
            exp = rule.expires_at or rule.expires
            msg = (
                f"Ignore rule for section={rule.section!r} "
                f"pattern={rule.described_pattern!r} expired on {exp}"
            )
            warnings.append(msg)
        else:
            active_rules.append(rule)

    if not active_rules:
        return diff, warnings

    filtered_diff: dict[str, Any] = {}
    for section, section_data in diff.items():
        if not isinstance(section_data, dict):
            filtered_diff[section] = section_data
            continue

        c_sec = _canonical_section_name(section)
        filtered_section: dict[str, Any] = {}

        for bucket, items in section_data.items():
            if not items:
                filtered_section[bucket] = items
                continue

            if isinstance(items, list):
                filtered_section[bucket] = [
                    item
                    for item in items
                    if not any(
                        r.matches(
                            c_sec,
                            item_name=n,
                            table_name=item.get("table_name") if isinstance(item, dict) else None,
                            object_name=n,
                            bucket=bucket,
                        )
                        for r in active_rules
                        for n in _extract_item_names(item)
                    )
                ]
            elif isinstance(items, dict):
                rem_dict: dict[str, Any] = {}
                for key, val in items.items():
                    if isinstance(val, list):
                        kept_items = []
                        for sub_item in val:
                            sub_names = _extract_item_names(sub_item)
                            if not any(
                                r.matches(
                                    c_sec,
                                    item_name=n,
                                    table_name=key,
                                    object_name=n,
                                    bucket=bucket,
                                )
                                for r in active_rules
                                for n in sub_names
                            ):
                                kept_items.append(sub_item)
                        if kept_items:
                            rem_dict[key] = kept_items
                    else:
                        names = [str(key), *_extract_item_names(val)]
                        t_name = (
                            val.get("table_name")
                            if isinstance(val, dict)
                            else str(key).split(".")[0]
                        )
                        if not any(
                            r.matches(
                                c_sec, item_name=n, table_name=t_name, object_name=n, bucket=bucket
                            )
                            for r in active_rules
                            for n in names
                        ):
                            rem_dict[key] = val
                filtered_section[bucket] = rem_dict
            else:
                filtered_section[bucket] = items

        filtered_diff[section] = filtered_section

    return filtered_diff, warnings


def filter_diff_by_ignores(diff: dict[str, Any], ignore_rules: list[IgnoreRule]) -> dict[str, Any]:
    """Filter diff by ignore rules (convenience wrapper returning diff only)."""
    filtered, _ = filter_by_ignore_rules(diff, ignore_rules)
    return filtered


def load_baseline(baseline_path: Path | str) -> dict[str, Any]:
    """Load baseline diff report or diff dictionary from JSON file."""
    path = Path(baseline_path)
    if not path.exists():
        raise FileNotFoundError(f"Baseline file not found: {path}")

    with open(path) as handle:
        data = json.load(handle)

    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in baseline file {path}")

    if "diff" in data and isinstance(data["diff"], dict):
        return data["diff"]
    return data


def filter_baseline_drift(
    current_diff: dict[str, Any],
    baseline_diff: dict[str, Any],
) -> dict[str, Any]:
    """Subtract accepted baseline drift from current diff so only new drift is reported."""
    if not baseline_diff:
        return current_diff

    filtered_diff: dict[str, Any] = {}

    for section, sec_data in current_diff.items():
        if not isinstance(sec_data, dict):
            filtered_diff[section] = sec_data
            continue

        base_sec = baseline_diff.get(section, {})
        if not isinstance(base_sec, dict):
            base_sec = {}

        filtered_sec: dict[str, Any] = {}
        for bucket, items in sec_data.items():
            base_items = base_sec.get(bucket)

            if isinstance(items, dict):
                if isinstance(base_items, dict):
                    rem_dict: dict[str, Any] = {}
                    for k, v in items.items():
                        base_v = base_items.get(k)
                        if base_v is None:
                            rem_dict[k] = v
                        elif isinstance(v, list) and isinstance(base_v, list):
                            base_ser = {json.dumps(x, sort_keys=True) for x in base_v}
                            diff_list = [
                                x for x in v if json.dumps(x, sort_keys=True) not in base_ser
                            ]
                            if diff_list:
                                rem_dict[k] = diff_list
                        elif json.dumps(v, sort_keys=True) != json.dumps(base_v, sort_keys=True):
                            rem_dict[k] = v
                    filtered_sec[bucket] = rem_dict
                else:
                    filtered_sec[bucket] = items
            elif isinstance(items, list):
                if isinstance(base_items, list):
                    base_serialized = {json.dumps(x, sort_keys=True) for x in base_items}
                    filtered_sec[bucket] = [
                        x for x in items if json.dumps(x, sort_keys=True) not in base_serialized
                    ]
                else:
                    filtered_sec[bucket] = items
            else:
                filtered_sec[bucket] = items

        filtered_diff[section] = filtered_sec

    return filtered_diff


def filter_baseline(current_diff: dict[str, Any], baseline_diff: dict[str, Any]) -> dict[str, Any]:
    """Alias for filter_baseline_drift."""
    return filter_baseline_drift(current_diff, baseline_diff)


def summarize_severities(
    diff: dict[str, Any],
    custom_overrides: dict[str, Any] | None = None,
) -> dict[str, int]:
    """Count findings by severity level across all diff sections."""
    counts = {
        Severity.BLOCKING.value: 0,
        Severity.WARNING.value: 0,
        Severity.INFO.value: 0,
    }

    for section, sec_data in diff.items():
        if section in NON_DRIFT_SECTIONS:
            continue
        if not isinstance(sec_data, dict):
            continue
        for bucket in SEVERITY_BUCKETS:
            items = sec_data.get(bucket)
            if not items:
                continue
            sev = get_default_severity(section, bucket, custom_overrides)
            qty = len(items) if isinstance(items, (list, dict)) else 1
            counts[sev.value] += qty

    return counts


def calculate_severity(
    diff: dict[str, Any],
    custom_overrides: dict[str, Any] | None = None,
    overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Calculate severity breakdown, counts, and findings list for a diff."""
    effective_overrides = custom_overrides or overrides
    severities = summarize_severities(diff, effective_overrides)

    findings: list[dict[str, Any]] = []
    max_sev: Severity | None = None

    for section, sec_data in diff.items():
        if section in NON_DRIFT_SECTIONS:
            continue
        if not isinstance(sec_data, dict):
            continue
        for bucket in SEVERITY_BUCKETS:
            items = sec_data.get(bucket)
            if not items:
                continue
            sev = get_default_severity(section, bucket, effective_overrides)
            if max_sev is None or sev > max_sev:
                max_sev = sev

            if isinstance(items, list):
                for it in items:
                    findings.append(
                        {
                            "section": section,
                            "bucket": bucket,
                            "severity": sev.value,
                            "details": it,
                        }
                    )
            elif isinstance(items, dict):
                for k, it in items.items():
                    findings.append(
                        {
                            "section": section,
                            "bucket": bucket,
                            "key": k,
                            "severity": sev.value,
                            "details": it,
                        }
                    )

    has_drift = any(
        sec_data.get(bucket)
        for section, sec_data in diff.items()
        if section not in NON_DRIFT_SECTIONS and isinstance(sec_data, dict)
        for bucket in DRIFT_BUCKETS
    )
    return {
        "has_drift": has_drift,
        "max_severity": max_sev.value if max_sev is not None else "none",
        "counts": severities,
        "findings": findings,
    }


def apply_severity(
    diff: dict[str, Any],
    min_severity: Severity | str = Severity.INFO,
    custom_overrides: dict[str, Any] | None = None,
    overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Filter diff to only include findings at or above min_severity."""
    min_sev = Severity.from_str(min_severity)
    effective_overrides = custom_overrides or overrides
    input_diff = (
        diff["diff"]
        if isinstance(diff, dict) and "diff" in diff and isinstance(diff["diff"], dict)
        else diff
    )

    filtered_diff: dict[str, Any] = {}
    for section, sec_data in input_diff.items():
        if not isinstance(sec_data, dict):
            filtered_diff[section] = sec_data
            continue

        filtered_sec: dict[str, Any] = {}
        for bucket, items in sec_data.items():
            if bucket not in DRIFT_BUCKETS:
                filtered_sec[bucket] = items
                continue
            sev = get_default_severity(section, bucket, effective_overrides)
            if sev >= min_sev:
                filtered_sec[bucket] = items
            else:
                filtered_sec[bucket] = [] if isinstance(items, list) else {}

        filtered_diff[section] = filtered_sec

    return {
        "diff": filtered_diff,
        "min_severity": min_sev.value,
        "severities": summarize_severities(filtered_diff, effective_overrides),
    }
