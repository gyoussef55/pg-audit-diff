SELECT COALESCE(
    json_object_agg(
        CASE WHEN cardinality(COALESCE(%(schemas)s, ARRAY[%(schema)s])::text[]) = 1 THEN t.table_name ELSE t.schema_name || '.' || t.table_name END,
        json_build_object(
            'schema_name', t.schema_name,
            'table_name', t.table_name,
            'table_type', t.table_type,
            'persistence', t.persistence,
            'reloptions', t.reloptions,
            'tablespace', t.tablespace,
            'rls_enabled', t.rls_enabled,
            'rls_forced', t.rls_forced,
            'is_partitioned', t.is_partitioned,
            'is_partition', t.is_partition,
            'partition_key', t.partition_key,
            'partition_bound', t.partition_bound,
            'parent_table', t.parent_table,
            'parent_schema', t.parent_schema
        )
    ),
    '{}'::json
) AS tables
FROM (
    SELECT
        n.nspname AS schema_name,
        t.relname AS table_name,
        CASE t.relkind
            WHEN 'r' THEN 'table'
            WHEN 'p' THEN 'partitioned_table'
            WHEN 'v' THEN 'view'
            WHEN 'm' THEN 'materialized_view'
            WHEN 'f' THEN 'foreign_table'
            ELSE 'unknown'
        END AS table_type,
        CASE t.relpersistence
            WHEN 'u' THEN 'unlogged'
            WHEN 't' THEN 'temporary'
            ELSE 'permanent'
        END AS persistence,
        t.reloptions AS reloptions,
        ts.spcname AS tablespace,
        t.relrowsecurity AS rls_enabled,
        t.relforcerowsecurity AS rls_forced,
        (t.relkind = 'p') AS is_partitioned,
        t.relispartition AS is_partition,
        pg_get_partkeydef(t.oid) AS partition_key,
        pg_get_expr(t.relpartbound, t.oid) AS partition_bound,
        parent.relname AS parent_table,
        pn.nspname AS parent_schema
    FROM pg_class t
    JOIN pg_namespace n ON n.oid = t.relnamespace
    LEFT JOIN pg_tablespace ts ON ts.oid = t.reltablespace
    LEFT JOIN pg_inherits i ON i.inhrelid = t.oid
    LEFT JOIN pg_class parent ON parent.oid = i.inhparent
    LEFT JOIN pg_namespace pn ON pn.oid = parent.relnamespace
    WHERE n.nspname = ANY(COALESCE(%(schemas)s, ARRAY[%(schema)s]))
      AND t.relkind IN ('r', 'p', 'v', 'm', 'f')
    ORDER BY n.nspname, t.relname
) t;
