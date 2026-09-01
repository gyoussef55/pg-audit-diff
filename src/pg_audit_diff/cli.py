"""CLI for PostgreSQL schema comparison and drift reporting."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from pg_audit_diff import __version__
from pg_audit_diff.cli_helpers import (
    EXIT_ERROR,
    VALID_FAIL_ON,
    VALID_FORMATS,
    VALID_VERSION_POLICIES,
    apply_filters_and_build_report,
    combine_ignore_rules,
    emit_report,
    evaluate_exit,
    load_and_validate_snapshot,
    load_config_file,
    make_snapshot_options,
    validate_privileges_scope,
    write_output_file,
)
from pg_audit_diff.config import (
    redact_dsn,
    resolve_database_url,
)
from pg_audit_diff.connections import connect_readonly
from pg_audit_diff.diff import compare_snapshots
from pg_audit_diff.snapshot import build_schema_snapshot, filter_snapshot_tables

_load_snapshot = load_and_validate_snapshot
_snapshot_options = make_snapshot_options

app = typer.Typer(
    name="pg-audit-diff",
    help="Compare PostgreSQL schemas between databases or snapshot files.",
    no_args_is_help=True,
)
console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"pg-audit-diff {__version__}")
        raise typer.Exit(0)


@app.callback()
def main(
    _version: Annotated[
        bool,
        typer.Option(
            "--version", "-V", help="Show version", callback=_version_callback, is_eager=True
        ),
    ] = False,
) -> None:
    """PostgreSQL schema comparison tool."""


@app.command()
def compare(
    reference_url: Annotated[
        str | None, typer.Option("--reference-url", help="Reference DB URL")
    ] = None,
    compared_url: Annotated[
        str | None, typer.Option("--compared-url", help="Compared DB URL")
    ] = None,
    reference_profile: Annotated[
        str | None, typer.Option("--reference-profile", help="Reference profile")
    ] = None,
    compared_profile: Annotated[
        str | None, typer.Option("--compared-profile", help="Compared profile")
    ] = None,
    config: Annotated[Path | None, typer.Option("--config", help="YAML config file")] = None,
    ignore_config: Annotated[
        Path | None, typer.Option("--ignore-config", help="Ignore rules YAML")
    ] = None,
    baseline: Annotated[Path | None, typer.Option("--baseline", help="Baseline diff JSON")] = None,
    schema: Annotated[str, typer.Option("--schema", help="PostgreSQL schema")] = "public",
    all_schemas: Annotated[
        bool, typer.Option("--all-schemas", help="Compare all non-system schemas")
    ] = False,
    include_tables: Annotated[
        str | None, typer.Option("--include-tables", help="Include tables regex")
    ] = None,
    exclude_tables: Annotated[
        str | None, typer.Option("--exclude-tables", help="Exclude tables regex")
    ] = None,
    track_ordinal_position: Annotated[
        bool, typer.Option("--track-ordinal-position", help="Track column ordinal position")
    ] = False,
    include_privileges: Annotated[
        bool,
        typer.Option(
            "--include-privileges",
            help="Compare ownership and ACL grants (off by default; role names differ per env)",
        ),
    ] = False,
    migrations_schema: Annotated[
        str, typer.Option("--migrations-schema", help="Migrations schema")
    ] = "public",
    migrations_table: Annotated[
        str | None,
        typer.Option("--migrations-table", help="Migrations table (default: auto-detected)"),
    ] = None,
    skip_migrations: Annotated[
        bool, typer.Option("--skip-migrations", help="Skip migrations")
    ] = False,
    role: Annotated[str | None, typer.Option("--role", help="PostgreSQL role")] = None,
    reference_role: Annotated[str | None, typer.Option("--reference-role", help="Ref role")] = None,
    compared_role: Annotated[str | None, typer.Option("--compared-role", help="Cmp role")] = None,
    extension_version_policy: Annotated[
        str, typer.Option("--extension-version-policy", help="Extension version policy")
    ] = "exact",
    statement_timeout: Annotated[
        int | None, typer.Option("--statement-timeout", help="Timeout ms")
    ] = None,
    reference_snapshot: Annotated[
        Path | None, typer.Option("--reference-snapshot", help="Write ref snapshot")
    ] = None,
    compared_snapshot: Annotated[
        Path | None, typer.Option("--compared-snapshot", help="Write cmp snapshot")
    ] = None,
    output_file: Annotated[
        Path | None, typer.Option("--output-file", "-o", help="Report path")
    ] = None,
    output_format: Annotated[
        str, typer.Option("--format", help="Output format: json, text, markdown")
    ] = "json",
    fail_on: Annotated[
        str, typer.Option("--fail-on", help="Fail on: blocking, any, none")
    ] = "none",
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            help="Suppress progress and report on stdout (still writes -o; exit codes unchanged)",
        ),
    ] = False,
) -> None:
    """Compare live databases (reference = expected, compared = checked for drift)."""
    if output_format not in VALID_FORMATS:
        console.print(f"[red]--format must be one of: {', '.join(VALID_FORMATS)}[/red]")
        raise typer.Exit(EXIT_ERROR)
    if fail_on not in VALID_FAIL_ON:
        console.print(f"[red]--fail-on must be one of: {', '.join(VALID_FAIL_ON)}[/red]")
        raise typer.Exit(EXIT_ERROR)
    if extension_version_policy not in VALID_VERSION_POLICIES:
        console.print(
            f"[red]--extension-version-policy must be one of: {', '.join(VALID_VERSION_POLICIES)}[/red]"
        )
        raise typer.Exit(EXIT_ERROR)

    validate_privileges_scope(
        include_privileges=include_privileges,
        all_schemas=all_schemas,
        schema=schema,
    )

    cfg = load_config_file(config)
    ignore_cfg = load_config_file(ignore_config)
    profiles = cfg.profiles or None
    role_mapping = cfg.role_mapping or None
    try:
        ref_dsn = resolve_database_url(
            explicit_url=reference_url,
            profile_name=reference_profile,
            env_var="REFERENCE_DATABASE_URL",
            profiles=profiles,
            label="reference",
        )
        cmp_dsn = resolve_database_url(
            explicit_url=compared_url,
            profile_name=compared_profile,
            env_var="COMPARED_DATABASE_URL",
            profiles=profiles,
            label="compared",
        )
    except ValueError as exc:
        console.print(f"[red]{redact_dsn(str(exc))}[/red]")
        raise typer.Exit(EXIT_ERROR) from exc

    if ref_dsn == cmp_dsn:
        console.print("[red]Reference and compared URLs must differ[/red]")
        raise typer.Exit(EXIT_ERROR)

    snap_opts = make_snapshot_options(
        schema,
        migrations_schema,
        migrations_table,
        skip_migrations,
        all_schemas=all_schemas,
        include_privileges=include_privileges,
        include_tables=include_tables,
        exclude_tables=exclude_tables,
    )
    ref_label, cmp_label = (
        reference_profile or reference_url or "reference",
        compared_profile or compared_url or "compared",
    )

    if not quiet:
        console.print(
            f"[bold]Comparing[/bold] {redact_dsn(ref_label)} → {redact_dsn(cmp_label)} | schema={schema}"
        )

    ref_effective_role, cmp_effective_role = reference_role or role, compared_role or role

    try:
        with connect_readonly(ref_dsn, role=ref_effective_role) as ref_conn:
            if statement_timeout is not None:
                ref_conn.execute(f"SET statement_timeout = {int(statement_timeout)}")
            reference_data = build_schema_snapshot(ref_conn, snap_opts)
        with connect_readonly(cmp_dsn, role=cmp_effective_role) as cmp_conn:
            if statement_timeout is not None:
                cmp_conn.execute(f"SET statement_timeout = {int(statement_timeout)}")
            compared_data = build_schema_snapshot(cmp_conn, snap_opts)
    except Exception as exc:
        console.print(f"[red]Database error:[/red] {redact_dsn(str(exc))}")
        raise typer.Exit(EXIT_ERROR) from exc

    if reference_snapshot:
        write_output_file(reference_snapshot, json.dumps(reference_data, indent=2))
    if compared_snapshot:
        write_output_file(compared_snapshot, json.dumps(compared_data, indent=2))

    raw_diff = compare_snapshots(
        reference_data,
        compared_data,
        track_ordinal_position=track_ordinal_position,
        extension_version_policy=extension_version_policy,
        role_mapping=role_mapping,
    )
    report = apply_filters_and_build_report(
        raw_diff,
        baseline_path=baseline,
        ignore_rules=combine_ignore_rules(cfg, ignore_cfg),
        ref_label=ref_label,
        cmp_label=cmp_label,
        schema=schema,
    )
    emit_report(report, output_file=output_file, output_format=output_format, quiet=quiet)
    evaluate_exit(report, fail_on=fail_on)


@app.command("diff")
def diff_files(
    reference_snapshot: Annotated[
        Path, typer.Option("--reference-snapshot", help="Reference snapshot JSON")
    ],
    compared_snapshot: Annotated[
        Path, typer.Option("--compared-snapshot", help="Compared snapshot JSON")
    ],
    schema: Annotated[str, typer.Option("--schema", help="Schema label")] = "public",
    include_tables: Annotated[
        str | None, typer.Option("--include-tables", help="Include tables regex")
    ] = None,
    exclude_tables: Annotated[
        str | None, typer.Option("--exclude-tables", help="Exclude tables regex")
    ] = None,
    track_ordinal_position: Annotated[
        bool, typer.Option("--track-ordinal-position", help="Track column ordinal position")
    ] = False,
    extension_version_policy: Annotated[
        str, typer.Option("--extension-version-policy", help="Extension version policy")
    ] = "exact",
    config: Annotated[Path | None, typer.Option("--config", help="YAML config file")] = None,
    ignore_config: Annotated[
        Path | None, typer.Option("--ignore-config", help="Ignore rules YAML")
    ] = None,
    baseline: Annotated[Path | None, typer.Option("--baseline", help="Baseline diff JSON")] = None,
    output_file: Annotated[
        Path | None, typer.Option("--output-file", "-o", help="Report path")
    ] = None,
    output_format: Annotated[
        str, typer.Option("--format", help="Output format: json, text, markdown")
    ] = "json",
    fail_on: Annotated[
        str, typer.Option("--fail-on", help="Fail on: blocking, any, none")
    ] = "none",
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            help="Suppress report on stdout (still writes -o; exit codes unchanged)",
        ),
    ] = False,
) -> None:
    """Compare two snapshot JSON files (offline, no database)."""
    if output_format not in VALID_FORMATS:
        console.print(f"[red]--format must be one of: {', '.join(VALID_FORMATS)}[/red]")
        raise typer.Exit(EXIT_ERROR)
    if fail_on not in VALID_FAIL_ON:
        console.print(f"[red]--fail-on must be one of: {', '.join(VALID_FAIL_ON)}[/red]")
        raise typer.Exit(EXIT_ERROR)
    if extension_version_policy not in VALID_VERSION_POLICIES:
        console.print(
            f"[red]--extension-version-policy must be one of: {', '.join(VALID_VERSION_POLICIES)}[/red]"
        )
        raise typer.Exit(EXIT_ERROR)

    reference_data = load_and_validate_snapshot(reference_snapshot)
    compared_data = load_and_validate_snapshot(compared_snapshot)

    if include_tables or exclude_tables:
        opts = make_snapshot_options(
            schema,
            "public",
            None,
            False,
            include_tables=include_tables,
            exclude_tables=exclude_tables,
        )
        reference_data = filter_snapshot_tables(reference_data, opts)
        compared_data = filter_snapshot_tables(compared_data, opts)

    cfg = load_config_file(config)
    ignore_cfg = load_config_file(ignore_config)
    raw_diff = compare_snapshots(
        reference_data,
        compared_data,
        track_ordinal_position=track_ordinal_position,
        extension_version_policy=extension_version_policy,
        role_mapping=cfg.role_mapping or None,
    )
    report = apply_filters_and_build_report(
        raw_diff,
        baseline_path=baseline,
        ignore_rules=combine_ignore_rules(cfg, ignore_cfg),
        ref_label=str(reference_snapshot),
        cmp_label=str(compared_snapshot),
        schema=schema,
    )
    emit_report(report, output_file=output_file, output_format=output_format, quiet=quiet)
    evaluate_exit(report, fail_on=fail_on)


@app.command()
def snapshot(
    output_file: Annotated[Path, typer.Option("--output-file", "-o", help="Output JSON path")],
    database_url: Annotated[str | None, typer.Option("--database-url", help="Database URL")] = None,
    profile: Annotated[str | None, typer.Option("--profile", help="Profile from --config")] = None,
    config: Annotated[Path | None, typer.Option("--config", help="YAML config file")] = None,
    schema: Annotated[str, typer.Option("--schema", help="PostgreSQL schema")] = "public",
    all_schemas: Annotated[
        bool, typer.Option("--all-schemas", help="Snapshot all non-system schemas")
    ] = False,
    include_tables: Annotated[
        str | None, typer.Option("--include-tables", help="Include tables regex")
    ] = None,
    exclude_tables: Annotated[
        str | None, typer.Option("--exclude-tables", help="Exclude tables regex")
    ] = None,
    migrations_schema: Annotated[
        str, typer.Option("--migrations-schema", help="Migrations schema")
    ] = "public",
    migrations_table: Annotated[
        str | None,
        typer.Option("--migrations-table", help="Migrations table (default: auto-detected)"),
    ] = None,
    skip_migrations: Annotated[
        bool, typer.Option("--skip-migrations", help="Skip migrations")
    ] = False,
    include_privileges: Annotated[
        bool,
        typer.Option(
            "--include-privileges",
            help="Capture ownership and ACL grants (off by default; role names differ per env)",
        ),
    ] = False,
    role: Annotated[str | None, typer.Option("--role", help="PostgreSQL role")] = None,
    statement_timeout: Annotated[
        int | None, typer.Option("--statement-timeout", help="Timeout ms")
    ] = None,
) -> None:
    """Export a schema snapshot from one database."""
    validate_privileges_scope(
        include_privileges=include_privileges,
        all_schemas=all_schemas,
        schema=schema,
    )

    profiles = load_config_file(config).profiles or None
    try:
        dsn = resolve_database_url(
            explicit_url=database_url,
            profile_name=profile,
            env_var="DATABASE_URL",
            profiles=profiles,
            label="database",
            profile_flag="profile",
        )
    except ValueError as exc:
        console.print(f"[red]{redact_dsn(str(exc))}[/red]")
        raise typer.Exit(EXIT_ERROR) from exc

    snap_opts = make_snapshot_options(
        schema,
        migrations_schema,
        migrations_table,
        skip_migrations,
        all_schemas=all_schemas,
        include_privileges=include_privileges,
        include_tables=include_tables,
        exclude_tables=exclude_tables,
    )
    try:
        with connect_readonly(dsn, role=role) as conn:
            if statement_timeout is not None:
                conn.execute(f"SET statement_timeout = {int(statement_timeout)}")
            data = build_schema_snapshot(conn, snap_opts)
    except Exception as exc:
        console.print(f"[red]Database error:[/red] {redact_dsn(str(exc))}")
        raise typer.Exit(EXIT_ERROR) from exc

    write_output_file(output_file, json.dumps(data, indent=2))
    console.print(f"Snapshot written to {output_file}")
    raise typer.Exit(0)


def run() -> None:
    """Entry point for console_scripts."""
    try:
        app()
    except typer.Exit as exc:
        sys.exit(exc.exit_code)


if __name__ == "__main__":
    run()
