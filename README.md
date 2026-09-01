# pg-audit-diff

Compares PostgreSQL schemas between environments and reports what is missing, unexpected, or mismatched. Use it to catch schema drift before it turns into production errors — failed syncs, missing columns, or constraints that block writes.

Unlike many schema diff tools that match objects primarily by name, pg-audit-diff compares objects by structure and definition. Indexes and constraints are matched logically, so you see real gaps instead of noisy false positives from renamed objects.

## Install

Python 3.10+. PostgreSQL 14+ recommended.

```bash
git clone https://github.com/gyoussef55/pg-audit-diff.git
cd pg-audit-diff
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[binary]"
```

## Usage

Compare a **reference** database (expected) to a **compared** database (checked for drift).

Set URLs via env vars or `--reference-url` / `--compared-url`:

```bash
export REFERENCE_DATABASE_URL=postgresql://...
export COMPARED_DATABASE_URL=postgresql://...
```

```bash
pg-audit-diff compare
```

**Offline** — snapshot each side, then diff:

```bash
pg-audit-diff snapshot --database-url "$REFERENCE_DATABASE_URL" -o ref.json
pg-audit-diff snapshot --database-url "$COMPARED_DATABASE_URL" -o cmp.json
pg-audit-diff diff --reference-snapshot ref.json --compared-snapshot cmp.json
```

Or name connections in a YAML file (see `configs/profiles.example.yaml`) and select them with `--config` plus `--reference-profile` / `--compared-profile` (`--profile` for `snapshot`).

Exit codes: `0` no drift (or `--fail-on none`), `1` drift at the `--fail-on` threshold, `2` usage or runtime error.

## Report

Formats: `json` (default), `text`, `markdown`. Findings use buckets **missing** / **unexpected** / **mismatched** and severity **blocking** / **warning** / **info**.

Covers tables, columns, constraints (primary, unique, foreign, check, exclusion), indexes, types, views, functions, triggers, sequences, policies, extensions, migrations, and comments. Add `--include-privileges` for ownership and ACLs (single schema only).

Migration frameworks: Flyway, Alembic, TypeORM, Liquibase, Django, Rails, golang-migrate — auto-detected from the history table.

Not counted as drift: index renames with identical structure (`name_only` in JSON). PG version, encoding, and collation differences appear as environment warnings only (not in section counts).

Both sides must use the same schema names; a schema present on only one side is reported under `schemas`.

## Drift policy

YAML via `--config` or `--ignore-config`. Ignore keys: `ignore_rules`, `ignore`, or `rules`. `role_mapping` (`role_map` / `roles`) only with `--include-privileges` for privilege comparison:

```yaml
ignore_rules:
  - section: indexes
    name_pattern: "^idx_legacy_"

role_mapping:
  prod_app: stage_app
```

Save and subtract accepted drift. `-o baseline.json` writes the full report envelope; `--baseline` accepts that file or a raw `diff` object:

```bash
pg-audit-diff compare ... -o baseline.json
pg-audit-diff compare ... --baseline baseline.json --fail-on blocking
```

## Options

| Option | Description |
|--------|-------------|
| `--schema` | Schema or comma-separated list (default: `public`) |
| `--all-schemas` | `compare` / `snapshot` — all non-system schemas |
| `--include-tables` / `--exclude-tables` | Regex table filters (`compare`, `snapshot`, `diff`) |
| `--skip-migrations` | Skip migration history |
| `--migrations-schema` | Migration table schema (default: `public`) |
| `--migrations-table` | Migration table name, for non-standard names (default: auto-detected) |
| `--include-privileges` | Ownership and ACLs (off by default) |
| `--extension-version-policy` | `exact`, `major`, `minor`, `ignore` (default: `exact`) |
| `--role` / `--reference-role` / `--compared-role` | `SET ROLE` before introspection |
| `--track-ordinal-position` | Report column order changes |
| `--reference-snapshot` / `--compared-snapshot` | Snapshot JSON — inputs for `diff`, optional outputs for `compare` |
| `--baseline` / `--ignore-config` | Baseline file / separate ignore-rules file |
| `--format` / `-o` | Report format and output path (parent directories are created) |
| `--fail-on` | `none` (default), `any`, or `blocking` |
| `--quiet` | Suppress the report on stdout; `-o` and exit codes unaffected |
| `--statement-timeout` | Per-statement timeout in ms (`compare`, `snapshot`; default 30000) |

## License

MIT — see [LICENSE](LICENSE).
