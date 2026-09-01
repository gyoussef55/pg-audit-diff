"""CLI execution helpers for schema comparison, snapshots, and report emitting."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from pg_audit_diff.config import (
    Config,
    IgnoreRule,
    apply_ignore_rules,
    load_baseline,
    load_config,
    redact_dsn,
    subtract_baseline,
)
from pg_audit_diff.report import (
    build_report,
    format_markdown_report,
    format_text_report,
)
from pg_audit_diff.snapshot import (
    SNAPSHOT_VERSION,
    SnapshotOptions,
    load_snapshot_file,
    parse_schema_list,
)

EXIT_OK, EXIT_DRIFT, EXIT_ERROR = 0, 1, 2
CURRENT_SNAPSHOT_VERSION = SNAPSHOT_VERSION
VALID_FORMATS = ("json", "text", "markdown")
VALID_FAIL_ON = ("blocking", "any", "none")
VALID_VERSION_POLICIES = ("exact", "major", "minor", "ignore")

console = Console(stderr=True)


def parse_schemas(schema: str) -> tuple[str, ...]:
    """Parse comma-separated schema string into tuple of schema names."""
    return parse_schema_list(schema)


def validate_regex(pattern: str | None, option: str) -> None:
    """Reject an invalid table-filter regex before it reaches the comparison."""
    if pattern is None:
        return
    try:
        re.compile(pattern)
    except re.error as exc:
        console.print(f"[red]{option} is not a valid regular expression:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc


def make_snapshot_options(
    schema: str,
    migrations_schema: str,
    migrations_table: str | None,
    skip_migrations: bool,
    *,
    all_schemas: bool = False,
    include_privileges: bool = False,
    include_tables: str | None = None,
    exclude_tables: str | None = None,
) -> SnapshotOptions:
    """Construct a SnapshotOptions dataclass instance."""
    validate_regex(include_tables, "--include-tables")
    validate_regex(exclude_tables, "--exclude-tables")
    schemas_tuple = parse_schemas(schema)
    return SnapshotOptions(
        schema=schema,
        schemas=schemas_tuple,
        all_schemas=all_schemas,
        migrations_schema=migrations_schema,
        migrations_table=migrations_table,
        include_migrations=not skip_migrations,
        include_privileges=include_privileges,
        include_tables=include_tables,
        exclude_tables=exclude_tables,
    )


def write_output_file(path: Path, content: str) -> None:
    """Write text to ``path``, creating parent directories, and exit cleanly on I/O errors."""
    try:
        parent = path.parent
        if str(parent):
            parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    except OSError as exc:
        console.print(f"[red]Failed to write {path}:[/red] {exc.strerror or exc}")
        raise typer.Exit(EXIT_ERROR) from exc


def load_and_validate_snapshot(path: Path) -> dict[str, Any]:
    """Load and validate snapshot format version."""
    try:
        return load_snapshot_file(path)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(EXIT_ERROR) from exc


def load_config_file(path: Path | None) -> Config:
    """Load a YAML config, turning a missing file or parse failure into a usage error.

    Every caller must route config loading through here: an unhandled parse error would
    otherwise surface as exit code 1, which callers read as "drift detected".
    """
    if path is None:
        return Config()
    if not path.exists():
        console.print(f"[red]Config file not found:[/red] {path}")
        raise typer.Exit(EXIT_ERROR)
    try:
        return load_config(path)
    except Exception as exc:
        console.print(f"[red]Failed to load config from {path}:[/red] {redact_dsn(str(exc))}")
        raise typer.Exit(EXIT_ERROR) from exc


def validate_privileges_scope(
    *,
    include_privileges: bool,
    all_schemas: bool,
    schema: str,
) -> None:
    """Reject privilege capture when more than one schema is in scope."""
    if not include_privileges:
        return
    if all_schemas:
        console.print(
            "[red]--include-privileges requires a single schema; do not use --all-schemas[/red]"
        )
        raise typer.Exit(EXIT_ERROR)
    if len(parse_schemas(schema)) != 1:
        console.print("[red]--include-privileges requires exactly one schema in --schema[/red]")
        raise typer.Exit(EXIT_ERROR)


def combine_ignore_rules(config: Config, ignore_config: Config) -> list[IgnoreRule]:
    """Merge ignore rules from the main config and a dedicated ignore-rules file."""
    return [*config.ignore_rules, *ignore_config.ignore_rules]


def apply_filters_and_build_report(
    raw_diff: dict[str, Any],
    *,
    baseline_path: Path | None,
    ignore_rules: list[IgnoreRule],
    ref_label: str,
    cmp_label: str,
    schema: str,
) -> dict[str, Any]:
    """Apply baseline subtraction, ignore filtering, and wrap diff in report envelope."""
    diff = raw_diff
    if baseline_path:
        try:
            base_diff = load_baseline(baseline_path)
            diff = subtract_baseline(diff, base_diff)
        except Exception as exc:
            console.print(f"[red]Failed to load baseline:[/red] {exc}")
            raise typer.Exit(EXIT_ERROR) from exc

    if ignore_rules:
        diff = apply_ignore_rules(diff, ignore_rules)

    return build_report(
        reference=redact_dsn(ref_label),
        compared=redact_dsn(cmp_label),
        schema=schema,
        diff=diff,
    )


def emit_report(
    report: dict[str, Any],
    *,
    output_file: Path | None,
    output_format: str,
    quiet: bool = False,
) -> None:
    """Format and write or print the diff report.

    Status messages go to stderr; the report body goes to stdout unless ``quiet``.
    """
    if output_format == "json":
        content = json.dumps(report, indent=2)
    elif output_format == "markdown":
        content = format_markdown_report(report)
    else:
        content = format_text_report(report)

    if output_file:
        write_output_file(output_file, content)
        if not quiet:
            console.print(f"Report written to {output_file}")
    elif not quiet:
        print(content)


def evaluate_exit(report: dict[str, Any], *, fail_on: str) -> None:
    """Determine CLI exit code based on fail_on threshold."""
    if fail_on == "blocking" and report.get("has_blocking_drift"):
        raise typer.Exit(EXIT_DRIFT)
    if fail_on == "any" and report.get("has_drift"):
        raise typer.Exit(EXIT_DRIFT)
    raise typer.Exit(EXIT_OK)
