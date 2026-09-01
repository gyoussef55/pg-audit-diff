"""PostgreSQL schema snapshot and logical diff library."""

from pg_audit_diff.__version__ import __version__
from pg_audit_diff.config import (
    Config,
    format_safe_error,
    load_config,
    load_ignore_rules,
    load_profiles,
    load_role_mapping,
    redact_dsn,
    resolve_database_url,
)
from pg_audit_diff.connections import connect_readonly, verify_connection
from pg_audit_diff.diff import compare_snapshots, has_drift
from pg_audit_diff.migrations_adapters import compare_migration_records, extract_migrations
from pg_audit_diff.policy import (
    DEFAULT_SECTION_SEVERITIES,
    DEFAULT_SEVERITY_MAP,
    IgnoreRule,
    Severity,
    apply_severity,
    calculate_severity,
    filter_baseline,
    filter_baseline_drift,
    filter_by_ignore_rules,
    filter_diff_by_ignores,
    get_default_severity,
    load_baseline,
)
from pg_audit_diff.privileges import compare_privileges
from pg_audit_diff.report import (
    REPORT_VERSION,
    build_report,
    format_markdown_report,
    format_text_report,
    summarize_diff,
    summarize_severities,
)
from pg_audit_diff.snapshot import SNAPSHOT_SECTIONS, SnapshotOptions, build_schema_snapshot

__all__ = [
    "DEFAULT_SECTION_SEVERITIES",
    "DEFAULT_SEVERITY_MAP",
    "REPORT_VERSION",
    "SNAPSHOT_SECTIONS",
    "Config",
    "IgnoreRule",
    "Severity",
    "SnapshotOptions",
    "__version__",
    "apply_severity",
    "build_report",
    "build_schema_snapshot",
    "calculate_severity",
    "compare_migration_records",
    "compare_privileges",
    "compare_snapshots",
    "connect_readonly",
    "extract_migrations",
    "filter_baseline",
    "filter_baseline_drift",
    "filter_by_ignore_rules",
    "filter_diff_by_ignores",
    "format_markdown_report",
    "format_safe_error",
    "format_text_report",
    "get_default_severity",
    "has_drift",
    "load_baseline",
    "load_config",
    "load_ignore_rules",
    "load_profiles",
    "load_role_mapping",
    "redact_dsn",
    "resolve_database_url",
    "summarize_diff",
    "summarize_severities",
    "verify_connection",
]
