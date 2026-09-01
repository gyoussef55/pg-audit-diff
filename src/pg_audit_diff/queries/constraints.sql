SELECT COALESCE(
    json_object_agg(table_key, cons_data),
    '{}'::json
) AS constraints
FROM (
    SELECT
        CASE WHEN cardinality(COALESCE(%(schemas)s, ARRAY[%(schema)s])::text[]) = 1 THEN t.relname ELSE n.nspname || '.' || t.relname END AS table_key,
        t.relname AS table_name,
        n.nspname AS schema_name,
        json_agg(
            json_build_object(
                'schema_name', n.nspname,
                'table_name', CASE WHEN cardinality(COALESCE(%(schemas)s, ARRAY[%(schema)s])::text[]) = 1 THEN t.relname ELSE n.nspname || '.' || t.relname END,
                'constraint_name', c.conname,
                'constraint_type', c.contype::text,
                'definition', pg_get_constraintdef(c.oid),
                'is_valid', c.convalidated,
                'is_deferrable', c.condeferrable
            )
            ORDER BY c.conname
        ) AS cons_data
    FROM pg_constraint c
    JOIN pg_class t ON t.oid = c.conrelid
    JOIN pg_namespace n ON t.relnamespace = n.oid
    WHERE n.nspname = ANY(COALESCE(%(schemas)s, ARRAY[%(schema)s]))
      AND c.contype IN ('c', 'x')
    GROUP BY n.nspname, t.relname
    ORDER BY n.nspname, t.relname
) t;
