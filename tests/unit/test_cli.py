"""Unit tests for CLI commands, report formatting (text, markdown), and DSN redaction."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from pg_audit_diff.cli import app
from pg_audit_diff.cli_helpers import emit_report
from pg_audit_diff.cli_helpers import load_and_validate_snapshot as _load_snapshot
from pg_audit_diff.config import redact_dsn
from pg_audit_diff.diff import compare_snapshots
from pg_audit_diff.report import build_report, format_markdown_report, format_text_report
from pg_audit_diff.snapshot import SNAPSHOT_VERSION, build_schema_snapshot

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _plain_cli_output(text: str) -> str:
    """Strip Rich/Click ANSI styling so help assertions work in CI."""
    return _ANSI_ESCAPE.sub("", text)


def _load_fixture(name: str) -> dict[str, Any]:
    with open(FIXTURES / name) as handle:
        data: dict[str, Any] = json.load(handle)
        return data


class _StubCursor:
    def __init__(self, row: dict[str, Any] | None) -> None:
        self._row = row

    def fetchone(self) -> dict[str, Any] | None:
        return self._row


class _StubConnection:
    """Minimal psycopg stand-in that lets the snapshot writer run without a server."""

    def __init__(self) -> None:
        self.statements: list[str] = []

    @contextmanager
    def transaction(self) -> Iterator[_StubConnection]:
        self.statements.append("BEGIN")
        yield self
        self.statements.append("COMMIT")

    def execute(self, query: str, params: Any = None) -> _StubCursor:
        self.statements.append(query)
        if "server_version" in query:
            return _StubCursor({"server_version": "16.3"})
        if "to_regclass" in query:
            return _StubCursor({"present": False})
        return _StubCursor({"result": None})


def test_snapshot_writer_emits_a_version_the_cli_accepts(tmp_path: Path) -> None:
    """Guards against the writer and reader disagreeing on the snapshot format version."""
    conn = _StubConnection()
    snapshot = build_schema_snapshot(conn)  # type: ignore[arg-type]
    assert snapshot["snapshot_version"] == SNAPSHOT_VERSION

    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(snapshot))
    assert _load_snapshot(path)["snapshot_version"] == snapshot["snapshot_version"]


def test_snapshot_reads_run_inside_one_transaction() -> None:
    """All catalog reads must share a transaction so the snapshot is a single point in time."""
    conn = _StubConnection()
    build_schema_snapshot(conn)  # type: ignore[arg-type]

    assert conn.statements[0] == "BEGIN"
    assert conn.statements[-1] == "COMMIT"
    assert "REPEATABLE READ READ ONLY" in conn.statements[1]


def test_diff_compares_two_snapshot_files(tmp_path: Path) -> None:
    reference = tmp_path / "reference.json"
    compared = tmp_path / "compared.json"
    reference.write_text(json.dumps(_load_fixture("reference.json")))
    compared.write_text(json.dumps(_load_fixture("compared_clean.json")))

    result = runner.invoke(
        app,
        [
            "diff",
            "--reference-snapshot",
            str(reference),
            "--compared-snapshot",
            str(compared),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["has_drift"] is False


def test_diff_rejects_snapshots_from_an_incompatible_version(tmp_path: Path) -> None:
    stale = tmp_path / "stale.json"
    data = _load_fixture("reference.json")
    data["snapshot_version"] = 999
    stale.write_text(json.dumps(data))
    current = tmp_path / "current.json"
    current.write_text(json.dumps(_load_fixture("compared_clean.json")))

    result = runner.invoke(
        app,
        [
            "diff",
            "--reference-snapshot",
            str(stale),
            "--compared-snapshot",
            str(current),
        ],
    )
    assert result.exit_code != 0
    assert "snapshot_version" in result.output


def test_redact_dsn_uri_formats() -> None:
    """redact_dsn must mask credentials in postgresql:// and postgres:// URIs."""
    # Standard password
    uri = "postgresql://app_user:supersecret123@db.prod.internal:5432/main_db"
    redacted = redact_dsn(uri)
    assert "supersecret123" not in redacted
    assert "app_user:***@db.prod.internal:5432/main_db" in redacted

    # postgres:// scheme with query parameters
    uri2 = "postgres://admin:my%20secret%20pass@10.0.0.5:5432/stage?sslmode=require"
    redacted2 = redact_dsn(uri2)
    assert "my%20secret%20pass" not in redacted2
    assert "admin:***@10.0.0.5:5432/stage?sslmode=require" in redacted2

    # URI without password should remain unchanged
    uri_no_pass = "postgresql://readonly@localhost:5432/analytics"
    assert redact_dsn(uri_no_pass) == uri_no_pass

    # Empty string or None
    assert redact_dsn("") == ""
    assert redact_dsn(None) == ""


def test_redact_dsn_conninfo_key_value() -> None:
    """redact_dsn must mask password in keyword-value conninfo strings."""
    conninfo = "host=localhost port=5432 user=pguser password=secretpass dbname=testdb"
    redacted = redact_dsn(conninfo)
    assert "secretpass" not in redacted
    assert "password=***" in redacted

    # Quoted password
    conninfo_quoted = 'host=db user=usr password="complex password!" dbname=app'
    redacted_quoted = redact_dsn(conninfo_quoted)
    assert "complex password!" not in redacted_quoted
    assert "password=***" in redacted_quoted


def test_format_text_report() -> None:
    """format_text_report should include metadata, drift status, and section counts."""
    ref = _load_fixture("reference.json")
    cmp_snap = _load_fixture("compared_missing_table.json")
    diff = compare_snapshots(ref, cmp_snap)
    report = build_report(reference="ref_db", compared="cmp_db", schema="public", diff=diff)

    text = format_text_report(report)
    assert "Schema compare: ref_db (reference) vs cmp_db (compared)" in text
    assert "Schema: public" in text
    assert "Drift detected: True" in text
    assert "Counts by section:" in text
    assert "tables:" in text


def test_format_markdown_report_with_drift() -> None:
    """format_markdown_report should render markdown summary table and changed objects."""
    ref = _load_fixture("reference.json")
    cmp_snap = _load_fixture("compared_column_mismatch.json")
    diff = compare_snapshots(ref, cmp_snap)
    report = build_report(reference="reference", compared="compared", schema="public", diff=diff)

    md = format_markdown_report(report)
    assert "## PostgreSQL Schema Diff Report" in md
    assert "- **Reference:** `reference`" in md
    assert "- **Compared:** `compared`" in md
    assert "- **Status:**" in md
    assert "### Section Summary" in md
    assert "| Section | Missing | Unexpected | Mismatched | Total | Status |" in md
    assert "### Changed Objects" in md


def test_format_markdown_report_clean_sync() -> None:
    """format_markdown_report with no drift should display In Sync status and no changed objects."""
    ref = _load_fixture("reference.json")
    diff = compare_snapshots(ref, ref)
    report = build_report(reference="prod", compared="staging", schema="public", diff=diff)

    md = format_markdown_report(report)
    assert "## PostgreSQL Schema Diff Report" in md
    assert "Schemas are in sync" in md
    assert "### Section Summary" in md
    assert "### Changed Objects" not in md


def test_cli_diff_offline_json_format(tmp_path: Path) -> None:
    """CLI 'diff' command with --format json should output valid JSON report."""
    ref_file = FIXTURES / "reference.json"
    cmp_file = FIXTURES / "compared_clean.json"

    result = runner.invoke(
        app,
        [
            "diff",
            "--reference-snapshot",
            str(ref_file),
            "--compared-snapshot",
            str(cmp_file),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["has_drift"] is False
    assert "summary" in payload


def test_cli_diff_offline_markdown_format(tmp_path: Path) -> None:
    """CLI 'diff' command with --format markdown should output markdown report."""
    ref_file = FIXTURES / "reference.json"
    cmp_file = FIXTURES / "compared_missing_table.json"
    out_file = tmp_path / "report.md"

    result = runner.invoke(
        app,
        [
            "diff",
            "--reference-snapshot",
            str(ref_file),
            "--compared-snapshot",
            str(cmp_file),
            "--format",
            "markdown",
            "-o",
            str(out_file),
        ],
    )
    assert result.exit_code == 0
    assert out_file.exists()
    content = out_file.read_text()
    assert "## PostgreSQL Schema Diff Report" in content
    assert "### Section Summary" in content


def test_cli_diff_fail_on_any() -> None:
    """CLI 'diff' with --fail-on any should exit with code 1 when drift is detected."""
    ref_file = FIXTURES / "reference.json"
    cmp_file = FIXTURES / "compared_missing_table.json"

    result = runner.invoke(
        app,
        [
            "diff",
            "--reference-snapshot",
            str(ref_file),
            "--compared-snapshot",
            str(cmp_file),
            "--fail-on",
            "any",
        ],
    )
    assert result.exit_code == 1


def test_cli_dsn_redaction_on_error() -> None:
    """CLI connection errors must redact database password from error output."""
    secret_url = "postgresql://myuser:secret_super_pass@127.0.0.1:54399/nonexistent_db"
    result = runner.invoke(
        app,
        [
            "compare",
            "--reference-url",
            secret_url,
            "--compared-url",
            "postgresql://myuser:secret_super_pass@127.0.0.1:54398/other_db",
        ],
    )
    assert result.exit_code == 2
    # Ensure raw secret password is not in output or stderr
    assert "secret_super_pass" not in result.stdout
    assert "secret_super_pass" not in result.stderr


def test_cli_diff_missing_snapshot_exits_cleanly() -> None:
    """Missing snapshot files must print a clear error and exit 2, not a traceback."""
    result = runner.invoke(
        app,
        [
            "diff",
            "--reference-snapshot",
            "/nonexistent/ref.json",
            "--compared-snapshot",
            "/nonexistent/cmp.json",
        ],
    )
    assert result.exit_code == 2
    assert "Snapshot file not found" in result.output
    assert "Traceback" not in result.output


def test_cli_snapshot_missing_url_mentions_profile_flag() -> None:
    """snapshot connection errors must reference --profile, not --database-profile."""
    result = runner.invoke(app, ["snapshot", "-o", "/tmp/out.json"])
    assert result.exit_code == 2
    assert "--profile" in result.output
    assert "--database-profile" not in result.output


def test_emit_report_quiet_writes_file_silently(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """--quiet must suppress stdout and status lines while still writing -o."""
    ref = _load_fixture("reference.json")
    cmp_snap = _load_fixture("compared_clean.json")
    diff = compare_snapshots(ref, cmp_snap)
    report = build_report(reference="ref", compared="cmp", schema="public", diff=diff)
    out_file = tmp_path / "report.json"

    emit_report(report, output_file=out_file, output_format="json", quiet=True)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert out_file.exists()


def test_invalid_table_filter_regex_exits_with_error_code() -> None:
    """A malformed --include-tables regex is a usage error (2), not drift (1)."""
    result = runner.invoke(
        app,
        [
            "diff",
            "--reference-snapshot",
            str(FIXTURES / "reference.json"),
            "--compared-snapshot",
            str(FIXTURES / "reference.json"),
            "--include-tables",
            "[",
        ],
    )
    assert result.exit_code == 2
    assert "--include-tables is not a valid regular expression" in result.output


def test_invalid_ignore_rule_regex_exits_with_error_code(tmp_path: Path) -> None:
    """Ignore-rule patterns are compiled at load time so typos surface as usage errors."""
    cfg = tmp_path / "ignore.yaml"
    cfg.write_text('ignore_rules:\n  - section: indexes\n    name_pattern: "["\n')
    result = runner.invoke(
        app,
        [
            "diff",
            "--reference-snapshot",
            str(FIXTURES / "reference.json"),
            "--compared-snapshot",
            str(FIXTURES / "compared_partial_index.json"),
            "--ignore-config",
            str(cfg),
        ],
    )
    assert result.exit_code == 2
    assert "Invalid regular expression in ignore rule" in result.output


def test_report_envelope_rejected_as_snapshot(tmp_path: Path) -> None:
    """Passing a report to --reference-snapshot must name the actual mistake."""
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps({"version": 1, "diff": {"tables": {}}}))
    result = runner.invoke(
        app,
        [
            "diff",
            "--reference-snapshot",
            str(report_file),
            "--compared-snapshot",
            str(FIXTURES / "reference.json"),
        ],
    )
    assert result.exit_code == 2
    assert "appears to be a diff report" in result.output


def test_emit_report_creates_missing_parent_directories(tmp_path: Path) -> None:
    """-o into a not-yet-existing directory must succeed rather than raise."""
    report = build_report(reference="ref", compared="cmp", schema="public", diff={})
    out_file = tmp_path / "nested" / "dir" / "report.json"

    emit_report(report, output_file=out_file, output_format="json", quiet=True)

    assert out_file.exists()


def test_diff_output_write_failure_exits_with_error_code(tmp_path: Path) -> None:
    """An unwritable -o path must exit 2 (error), never 1 (drift detected)."""
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    result = runner.invoke(
        app,
        [
            "diff",
            "--reference-snapshot",
            str(FIXTURES / "reference.json"),
            "--compared-snapshot",
            str(FIXTURES / "compared_clean.json"),
            "-o",
            str(blocker / "report.json"),
        ],
    )
    assert result.exit_code == 2
    assert "Failed to write" in result.output


def test_cli_diff_quiet_flag_suppresses_stdout() -> None:
    """diff supports --quiet like compare does."""
    result = runner.invoke(
        app,
        [
            "diff",
            "--reference-snapshot",
            str(FIXTURES / "reference.json"),
            "--compared-snapshot",
            str(FIXTURES / "compared_clean.json"),
            "--quiet",
        ],
    )
    assert result.exit_code == 0
    assert result.output.strip() == ""


def test_cli_compare_quiet_flag_help_text() -> None:
    """compare exposes --quiet with accurate help text."""
    result = runner.invoke(app, ["compare", "--help"])
    assert result.exit_code == 0
    help_text = _plain_cli_output(result.output)
    assert "--quiet" in help_text
    assert "Suppress progress and report on" in help_text


def test_cli_compare_rejects_include_privileges_with_all_schemas() -> None:
    result = runner.invoke(
        app,
        [
            "compare",
            "--reference-url",
            "postgresql://u:p@127.0.0.1:54399/db",
            "--compared-url",
            "postgresql://u:p@127.0.0.1:54398/db",
            "--include-privileges",
            "--all-schemas",
        ],
    )
    assert result.exit_code == 2
    assert "single schema" in result.output


def test_cli_compare_rejects_include_privileges_with_multi_schema() -> None:
    result = runner.invoke(
        app,
        [
            "compare",
            "--reference-url",
            "postgresql://u:p@127.0.0.1:54399/db",
            "--compared-url",
            "postgresql://u:p@127.0.0.1:54398/db",
            "--include-privileges",
            "--schema",
            "public,analytics",
        ],
    )
    assert result.exit_code == 2
    assert "exactly one schema" in result.output


def test_cli_diff_role_mapping_maps_owners_across_environments(tmp_path: Path) -> None:
    ref_data = _load_fixture("reference.json")
    cmp_data = _load_fixture("compared_clean.json")

    # Add privileges with different roles
    ref_data["privileges"] = {
        "tables": {
            "users": {
                "object_name": "users",
                "owner": "prod_owner",
                "acl": [],
            }
        }
    }
    cmp_data["privileges"] = {
        "tables": {
            "users": {
                "object_name": "users",
                "owner": "stage_owner",
                "acl": [],
            }
        }
    }

    ref_file = tmp_path / "ref.json"
    cmp_file = tmp_path / "cmp.json"
    ref_file.write_text(json.dumps(ref_data))
    cmp_file.write_text(json.dumps(cmp_data))

    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("role_mapping:\n  prod_owner: stage_owner\n")

    result = runner.invoke(
        app,
        [
            "diff",
            "--reference-snapshot",
            str(ref_file),
            "--compared-snapshot",
            str(cmp_file),
            "--config",
            str(cfg_file),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["has_drift"] is False


def _diff_with_config(cfg: Path, *, command: str = "diff") -> Any:
    return runner.invoke(
        app,
        [
            command,
            "--reference-snapshot",
            str(FIXTURES / "reference.json"),
            "--compared-snapshot",
            str(FIXTURES / "compared_partial_index.json"),
            "--config",
            str(cfg),
        ],
    )


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("role_mapping:\n  - not_a_mapping\n", "role_mapping"),
        ("ignore_rules:\n  not_a_list: true\n", "ignore_rules"),
        ("profiles:\n  ref: 12345\n", "must be a URL string"),
        (": : :\n", "Failed to load config"),
    ],
)
def test_broken_config_is_a_usage_error_not_drift(tmp_path: Path, body: str, expected: str) -> None:
    """A bad --config must exit 2, never 1: callers read exit 1 as 'drift detected'."""
    cfg = tmp_path / "config.yaml"
    cfg.write_text(body)

    result = _diff_with_config(cfg)

    assert result.exit_code == 2, f"expected usage error, got {result.exit_code}"
    assert "Traceback" not in result.output
    assert expected in result.output


def test_missing_config_file_is_a_usage_error() -> None:
    result = _diff_with_config(Path("/nonexistent/config.yaml"))
    assert result.exit_code == 2
    assert "Config file not found" in result.output


def test_config_tolerates_keys_that_are_not_profiles(tmp_path: Path) -> None:
    """An unrelated top-level key must not be mistaken for a malformed profile."""
    cfg = tmp_path / "config.yaml"
    cfg.write_text('version: 1\nignore_rules:\n  - section: indexes\n    name_pattern: "^idx_"\n')

    result = _diff_with_config(cfg)

    assert result.exit_code == 0, result.output
    assert "Traceback" not in result.output
