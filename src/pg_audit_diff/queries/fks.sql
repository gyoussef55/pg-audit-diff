WITH filtered_tables AS (
    SELECT
        t.oid AS table_oid,
        n.nspname AS schema_name,
        CASE WHEN cardinality(COALESCE(%(schemas)s, ARRAY[%(schema)s])::text[]) = 1 THEN t.relname ELSE n.nspname || '.' || t.relname END AS table_name
    FROM pg_class t
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = ANY(COALESCE(%(schemas)s, ARRAY[%(schema)s])) AND t.relkind IN ('r', 'p')
), fks_pairs AS (
    SELECT
        c.conname AS constraint_name,
        src.schema_name,
        src.table_name,
        tn.nspname AS referenced_schema,
        tgt.relname AS referenced_table,
        COALESCE(ARRAY_AGG(sa.attname ORDER BY x.ordinality), '{}') AS columns,
        COALESCE(ARRAY_AGG(ta.attname ORDER BY x.ordinality), '{}') AS referenced_columns,
        CASE c.confdeltype
            WHEN 'a' THEN 'NO ACTION'
            WHEN 'r' THEN 'RESTRICT'
            WHEN 'c' THEN 'CASCADE'
            WHEN 'n' THEN 'SET NULL'
            WHEN 'd' THEN 'SET DEFAULT'
            ELSE 'NO ACTION'
        END AS on_delete,
        CASE c.confupdtype
            WHEN 'a' THEN 'NO ACTION'
            WHEN 'r' THEN 'RESTRICT'
            WHEN 'c' THEN 'CASCADE'
            WHEN 'n' THEN 'SET NULL'
            WHEN 'd' THEN 'SET DEFAULT'
            ELSE 'NO ACTION'
        END AS on_update,
        c.convalidated AS is_valid,
        c.condeferrable AS is_deferrable
    FROM filtered_tables src
    JOIN pg_constraint c ON c.conrelid = src.table_oid AND c.contype = 'f'
    JOIN pg_class tgt ON tgt.oid = c.confrelid
    JOIN pg_namespace tn ON tn.oid = tgt.relnamespace
    JOIN unnest(c.conkey) WITH ORDINALITY x(attnum, ordinality) ON true
    JOIN pg_attribute sa ON sa.attrelid = src.table_oid AND sa.attnum = x.attnum
    JOIN pg_attribute ta ON ta.attrelid = tgt.oid AND ta.attnum = c.confkey[x.ordinality]
    GROUP BY
        c.conname,
        src.schema_name,
        src.table_name,
        tn.nspname,
        tgt.relname,
        c.confdeltype,
        c.confupdtype,
        c.convalidated,
        c.condeferrable
    ORDER BY src.schema_name, src.table_name, c.conname
)
SELECT COALESCE(
    json_agg(
        json_build_object(
            'constraint_name', constraint_name,
            'schema_name', schema_name,
            'table_name', table_name,
            'referenced_schema', referenced_schema,
            'referenced_table', referenced_table,
            'columns', columns,
            'referenced_columns', referenced_columns,
            'on_delete', on_delete,
            'on_update', on_update,
            'is_valid', is_valid,
            'is_deferrable', is_deferrable
        )
    ),
    '[]'::json
) AS foreign_keys
FROM fks_pairs;
