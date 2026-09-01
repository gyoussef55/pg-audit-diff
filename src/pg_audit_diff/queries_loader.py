"""Load packaged SQL query files."""

from __future__ import annotations

import re
from importlib import resources

_IDENT_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def validate_sql_identifier(name: str, label: str) -> str:
    if not _IDENT_RE.match(name):
        raise ValueError(f"Invalid SQL identifier for {label}: {name!r}")
    return name


def load_query(name: str) -> str:
    path = resources.files("pg_audit_diff.queries").joinpath(f"{name}.sql")
    return path.read_text(encoding="utf-8")


def load_migrations_query(migrations_schema: str, migrations_table: str) -> str:
    schema = validate_sql_identifier(migrations_schema, "migrations_schema")
    table = validate_sql_identifier(migrations_table, "migrations_table")
    template = load_query("migrations")
    return template.replace("{migrations_schema}", schema).replace("{migrations_table}", table)
