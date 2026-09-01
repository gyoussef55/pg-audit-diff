WITH filtered_tables AS (
    SELECT
        t.oid AS table_oid,
        n.nspname AS schema_name,
        CASE WHEN cardinality(COALESCE(%(schemas)s, ARRAY[%(schema)s])::text[]) = 1 THEN t.relname ELSE n.nspname || '.' || t.relname END AS table_name
    FROM pg_class t
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = ANY(COALESCE(%(schemas)s, ARRAY[%(schema)s])) AND t.relkind IN ('r', 'p')
), ucs_dedup AS (
    SELECT
        t.schema_name,
        t.table_name,
        c.conname AS constraint_name,
        COALESCE(ARRAY_AGG(a.attname ORDER BY x.ordinality), '{}') AS columns,
        c.convalidated AS is_valid,
        c.condeferrable AS is_deferrable
    FROM filtered_tables t
    JOIN pg_constraint c ON c.conrelid = t.table_oid AND c.contype = 'u'
    JOIN unnest(c.conkey) WITH ORDINALITY x(attnum, ordinality) ON true
    JOIN pg_attribute a ON a.attrelid = t.table_oid AND a.attnum = x.attnum
    GROUP BY t.schema_name, t.table_name, c.conname, c.convalidated, c.condeferrable
    ORDER BY t.schema_name, t.table_name, c.conname
)
SELECT COALESCE(
    json_agg(
        json_build_object(
            'schema_name', schema_name,
            'table_name', table_name,
            'constraint_name', constraint_name,
            'columns', columns,
            'is_valid', is_valid,
            'is_deferrable', is_deferrable
        )
    ),
    '[]'::json
) AS unique_constraints
FROM ucs_dedup;
