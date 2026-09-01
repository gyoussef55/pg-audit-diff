"""Report wrapping, severity classification, and human-readable summaries."""

from __future__ import annotations

from typing import Any

from pg_audit_diff.__version__ import __version__
from pg_audit_diff.diff import DRIFT_BUCKETS, has_drift
from pg_audit_diff.severity import Severity, get_default_severity

REPORT_VERSION = 1

NON_DRIFT_SECTIONS: frozenset[str] = frozenset({"server_context"})

BLOCKING_SEVERITY = Severity.BLOCKING.value
WARNING_SEVERITY = Severity.WARNING.value
INFO_SEVERITY = Severity.INFO.value


def classify_severity(section: str, bucket: str) -> str:
    """Classify the severity of a diff finding using the shared severity defaults."""
    return get_default_severity(section, bucket).value


def _bucket_count(section: str, bucket: str, value: Any) -> int:
    """Accurately count items inside a bucket."""
    if not value:
        return 0
    if section == "columns":
        if isinstance(value, dict):
            return sum(len(cols) for cols in value.values() if isinstance(cols, (list, dict)))
        if isinstance(value, list):
            return len(value)
        return 1
    if isinstance(value, (list, dict)):
        return len(value)
    return 1


def summarize_diff(diff: dict[str, Any]) -> dict[str, dict[str, int]]:
    """Count items per section and bucket."""
    summary: dict[str, dict[str, int]] = {}
    for section, data in diff.items():
        if section in NON_DRIFT_SECTIONS:
            continue
        if not isinstance(data, dict):
            continue
        if not set(DRIFT_BUCKETS) <= set(data.keys()):
            continue
        summary[section] = {
            "missing": _bucket_count(section, "missing", data.get("missing")),
            "unexpected": _bucket_count(section, "unexpected", data.get("unexpected")),
            "mismatched": _bucket_count(section, "mismatched", data.get("mismatched")),
        }
    return summary


def summarize_severities(diff: dict[str, Any]) -> dict[str, int]:
    """Calculate aggregate counts for blocking, warning, and info severities."""
    counts: dict[str, int] = {
        BLOCKING_SEVERITY: 0,
        WARNING_SEVERITY: 0,
        INFO_SEVERITY: 0,
    }
    for section, data in diff.items():
        if section in NON_DRIFT_SECTIONS:
            continue
        if not isinstance(data, dict):
            continue
        for bucket in DRIFT_BUCKETS:
            item_count = _bucket_count(section, bucket, data.get(bucket))
            if item_count > 0:
                severity = classify_severity(section, bucket)
                counts[severity] = counts.get(severity, 0) + item_count
    return counts


def extract_server_context_warnings(diff: dict[str, Any]) -> list[str]:
    """Extract human-readable warning messages for server context divergence."""
    warnings: list[str] = []
    sc = diff.get("server_context")
    if isinstance(sc, dict):
        mismatched = sc.get("mismatched")
        if isinstance(mismatched, dict):
            for attr, vals in mismatched.items():
                if isinstance(vals, dict) and "expected" in vals and "actual" in vals:
                    warnings.append(
                        f"Server context mismatch on {attr}: "
                        f"expected {vals['expected']!r}, actual {vals['actual']!r}"
                    )
                else:
                    warnings.append(f"Server context mismatch on {attr}: {vals}")
    return warnings


def extract_duplicate_index_warnings(diff: dict[str, Any]) -> list[str]:
    """Extract human-readable warning messages for duplicate indexes detected within the same database."""
    warnings: list[str] = []
    idx_diff = diff.get("indexes")
    if isinstance(idx_diff, dict):
        duplicates = idx_diff.get("duplicates")
        if isinstance(duplicates, dict):
            for side in ("reference", "compared"):
                side_dupes = duplicates.get(side, [])
                if isinstance(side_dupes, list):
                    for dupe in side_dupes:
                        if isinstance(dupe, dict):
                            tbl = dupe.get("table_name") or "unknown"
                            cols = ", ".join(str(c) for c in dupe.get("columns", []))
                            names = ", ".join(str(n) for n in dupe.get("index_names", []))
                            warnings.append(
                                f"Duplicate indexes in {side} database on '{tbl}({cols})': {names}"
                            )
    return warnings


OBJECT_SECTIONS = (
    "primary_keys",
    "unique_constraints",
    "foreign_keys",
    "check_constraints",
    "exclusion_constraints",
    "indexes",
    "policies",
)


def _unwrap_change(item: Any) -> Any:
    """Return the reference side of a ``{expected, actual}`` mismatch wrapper."""
    if isinstance(item, dict) and "expected" in item and "actual" in item:
        expected = item["expected"]
        if isinstance(expected, dict):
            return expected
    return item


def _object_label(key: str, item: Any) -> str:
    """Build a ``table.object`` label, falling back to the identity key."""
    if isinstance(item, dict):
        table = str(item.get("table_name") or "")
        name = str(
            item.get("constraint_name") or item.get("index_name") or item.get("policy_name") or ""
        )
        if table and name:
            return f"{table}.{name}"
        if name:
            return name
        columns = item.get("columns")
        if table and columns:
            return f"{table}({', '.join(str(c) for c in columns)})"
    parts = key.split("|")
    if len(parts) == 2:
        return ".".join(parts)
    return key


def _environment_warning_count(warnings: list[str]) -> int:
    return sum(1 for w in warnings if w.startswith("Server context mismatch"))


def extract_object_names(section: str, bucket: str, data: Any) -> list[str]:
    """Extract clean, human-readable object names from a diff section bucket."""
    if not data:
        return []
    if section in ("tables", "schemas"):
        if isinstance(data, dict):
            return [str(k) for k in data]
        if isinstance(data, list):
            return [str(x) for x in data]
    elif section == "columns":
        names: list[str] = []
        if isinstance(data, dict):
            for table, cols in data.items():
                if isinstance(cols, list):
                    for item in cols:
                        if isinstance(item, str):
                            names.append(f"{table}.{item}")
                        elif isinstance(item, dict):
                            for col_name in item:
                                names.append(f"{table}.{col_name}")
                elif isinstance(cols, dict):
                    for col_name in cols:
                        names.append(f"{table}.{col_name}")
        return names
    elif section in OBJECT_SECTIONS:
        if isinstance(data, dict):
            return [_object_label(str(k), _unwrap_change(v)) for k, v in data.items()]
        if isinstance(data, list):
            return [str(x) for x in data]
        return []
    elif section == "server_context":
        if isinstance(data, dict):
            return [
                (
                    f"{k} (expected: {v['expected']}, actual: {v['actual']})"
                    if isinstance(v, dict) and "expected" in v and "actual" in v
                    else str(k)
                )
                for k, v in data.items()
            ]
        if isinstance(data, list):
            return [str(x) for x in data]
    elif section in ("types", "extensions", "functions", "triggers", "migrations", "privileges"):
        if isinstance(data, dict):
            return [str(k) for k in data]
        if isinstance(data, list):
            return [str(x) for x in data]

    if isinstance(data, dict):
        return [str(k) for k in data]
    if isinstance(data, list):
        return [str(x) for x in data]
    return [str(data)]


def build_report(
    *,
    reference: str,
    compared: str,
    schema: str,
    diff: dict[str, Any],
) -> dict[str, Any]:
    """Wrap a diff payload in a versioned report envelope (version 1)."""
    summary = summarize_diff(diff)
    severity_counts = summarize_severities(diff)
    drift_detected = has_drift(diff)
    blocking_drift = severity_counts.get(BLOCKING_SEVERITY, 0) > 0
    warnings = extract_server_context_warnings(diff)
    warnings.extend(extract_duplicate_index_warnings(diff))

    return {
        "version": REPORT_VERSION,
        "tool_version": __version__,
        "reference": reference,
        "compared": compared,
        "schema": schema,
        "has_drift": drift_detected,
        "has_blocking_drift": blocking_drift,
        "summary": summary,
        "severity_counts": severity_counts,
        "warnings": warnings,
        "diff": diff,
    }


def format_text_report(report: dict[str, Any]) -> str:
    """Render a human-readable text summary with section counts and changed objects."""
    ref = report.get("reference", "")
    cmp_label = report.get("compared", "")
    lines: list[str] = [
        f"Schema compare: {ref} (reference) vs {cmp_label} (compared)",
        f"Schema: {report.get('schema', '')}",
    ]

    warnings = report.get("warnings", [])
    env_warning_count = _environment_warning_count(warnings)
    if warnings:
        lines.append("")
        lines.append("Warnings:")
        for w in warnings:
            lines.append(f"  [!] {w}")

    severities = report.get("severity_counts", {})
    if report.get("has_drift"):
        blocking = severities.get(BLOCKING_SEVERITY, 0)
        warning = severities.get(WARNING_SEVERITY, 0)
        info = severities.get(INFO_SEVERITY, 0)
        lines.append(f"Drift detected: True (blocking={blocking}, warning={warning}, info={info})")
    else:
        lines.append("Drift detected: False")
        if env_warning_count:
            lines.append(
                f"Environment warnings: {env_warning_count} "
                "(server version/encoding/collation differ)"
            )

    lines.append("")
    lines.append("Counts by section:")

    has_counts = False
    for section, counts in report.get("summary", {}).items():
        if section in NON_DRIFT_SECTIONS:
            continue
        if not isinstance(counts, dict):
            continue
        missing = counts.get("missing", 0)
        unexpected = counts.get("unexpected", 0)
        mismatched = counts.get("mismatched", 0)
        total = missing + unexpected + mismatched
        if total == 0:
            continue
        has_counts = True
        lines.append(
            f"  {section}: missing={missing} unexpected={unexpected} mismatched={mismatched}"
        )

    if not has_counts:
        lines.append("  (all in sync)")

    changed_lines: list[str] = []
    diff_data = report.get("diff", {})
    if isinstance(diff_data, dict):
        for section, sec_dict in diff_data.items():
            if section in NON_DRIFT_SECTIONS:
                continue
            if not isinstance(sec_dict, dict):
                continue
            for bucket in DRIFT_BUCKETS:
                bucket_data = sec_dict.get(bucket)
                if not bucket_data:
                    continue
                names = extract_object_names(section, bucket, bucket_data)
                if names:
                    changed_lines.append(f"  {bucket.capitalize()} {section}: {', '.join(names)}")

    if changed_lines:
        lines.append("")
        lines.append("Changed objects:")
        lines.extend(changed_lines)

    return "\n".join(lines)


def format_markdown_report(report: dict[str, Any]) -> str:
    """Render a formatted markdown report suitable for PR comments and CI annotations."""
    reference = report.get("reference", "")
    compared = report.get("compared", "")
    schema = report.get("schema", "")
    has_drift_flag = report.get("has_drift", False)
    has_blocking = report.get("has_blocking_drift", False)
    severities = report.get("severity_counts", {})

    warnings = report.get("warnings", [])
    env_warning_count = _environment_warning_count(warnings)

    if not has_drift_flag:
        status_line = "🟢 **Schemas are in sync**"
    elif has_blocking:
        status_line = "🔴 **Blocking drift detected**"
    else:
        status_line = "🟡 **Non-blocking drift detected**"

    lines: list[str] = [
        "## PostgreSQL Schema Diff Report",
        "",
        f"- **Reference:** `{reference}`",
        f"- **Compared:** `{compared}`",
        f"- **Schema:** `{schema}`",
        f"- **Status:** {status_line}",
    ]
    if not has_drift_flag and env_warning_count:
        lines.append(
            f"- **Environment warnings:** `{env_warning_count}` "
            "(server version/encoding/collation differ)"
        )
    if warnings:
        lines.append("")
        lines.append("### ⚠️ Warnings")
        lines.append("")
        for w in warnings:
            lines.append(f"- {w}")

    if has_drift_flag:
        b_cnt = severities.get(BLOCKING_SEVERITY, 0)
        w_cnt = severities.get(WARNING_SEVERITY, 0)
        i_cnt = severities.get(INFO_SEVERITY, 0)
        lines.append(
            f"- **Severities:** `Blocking: {b_cnt}` | `Warning: {w_cnt}` | `Info: {i_cnt}`"
        )

    lines.append("")
    lines.append("### Section Summary")
    lines.append("")
    lines.append("| Section | Missing | Unexpected | Mismatched | Total | Status |")
    lines.append("|:---|:---:|:---:|:---:|:---:|:---|")

    summary = report.get("summary", {})
    any_sections_drifted = False
    if isinstance(summary, dict):
        for section, counts in summary.items():
            if section in NON_DRIFT_SECTIONS:
                continue
            if not isinstance(counts, dict):
                continue
            m = counts.get("missing", 0)
            u = counts.get("unexpected", 0)
            mm = counts.get("mismatched", 0)
            total = m + u + mm
            if total == 0:
                continue
            any_sections_drifted = True
            section_sev = INFO_SEVERITY
            for bucket, count in (("missing", m), ("mismatched", mm), ("unexpected", u)):
                if count > 0:
                    sev = classify_severity(section, bucket)
                    if sev == BLOCKING_SEVERITY:
                        section_sev = BLOCKING_SEVERITY
                        break
                    if sev == WARNING_SEVERITY:
                        section_sev = WARNING_SEVERITY

            sev_badge = {
                BLOCKING_SEVERITY: "🔴 Blocking",
                WARNING_SEVERITY: "🟡 Warning",
                INFO_SEVERITY: "🔵 Info",
            }.get(section_sev, "🟡 Warning")

            lines.append(f"| {section} | {m} | {u} | {mm} | {total} | {sev_badge} |")

    if not any_sections_drifted:
        lines.append("| *(all sections)* | 0 | 0 | 0 | 0 | 🟢 In sync |")

    detail_rows: list[str] = []
    diff_data = report.get("diff", {})
    if isinstance(diff_data, dict):
        for section, sec_dict in diff_data.items():
            if section in NON_DRIFT_SECTIONS:
                continue
            if not isinstance(sec_dict, dict):
                continue
            for bucket in DRIFT_BUCKETS:
                bucket_data = sec_dict.get(bucket)
                if not bucket_data:
                    continue
                names = extract_object_names(section, bucket, bucket_data)
                sev = classify_severity(section, bucket)
                sev_badge = {
                    BLOCKING_SEVERITY: "🔴 Blocking",
                    WARNING_SEVERITY: "🟡 Warning",
                    INFO_SEVERITY: "🔵 Info",
                }.get(sev, "🟡 Warning")
                bucket_label = bucket.capitalize()
                for name in names:
                    detail_rows.append(f"| {section} | {bucket_label} | `{name}` | {sev_badge} |")

    if detail_rows:
        lines.append("")
        lines.append("### Changed Objects")
        lines.append("")
        lines.append("| Section | Change Type | Object | Severity |")
        lines.append("|:---|:---|:---|:---|")
        lines.extend(detail_rows)

    return "\n".join(lines)
