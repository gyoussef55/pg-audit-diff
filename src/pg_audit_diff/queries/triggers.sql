SELECT COALESCE(
    json_object_agg(trigger_key, json_build_object(
        'schema_name', schema_name,
        'table_name', table_name,
        'trigger_name', trigger_name,
        'events', events,
        'action_timing', action_timing,
        'orientation', orientation,
        'action_statement', action_statement,
        'is_enabled', is_enabled
    )),
    '{}'::json
) AS triggers
FROM (
    SELECT
        n.nspname AS schema_name,
        CASE WHEN cardinality(COALESCE(%(schemas)s, ARRAY[%(schema)s])::text[]) = 1 THEN t.relname ELSE n.nspname || '.' || t.relname END AS table_name,
        tr.tgname AS trigger_name,
        CONCAT(n.nspname, '.', t.relname, '.', tr.tgname) AS trigger_key,
        ARRAY_REMOVE(
            ARRAY[
                CASE WHEN (tr.tgtype::int & 4) != 0 THEN 'INSERT' ELSE NULL END,
                CASE WHEN (tr.tgtype::int & 8) != 0 THEN 'DELETE' ELSE NULL END,
                CASE WHEN (tr.tgtype::int & 16) != 0 THEN 'UPDATE' ELSE NULL END,
                CASE WHEN (tr.tgtype::int & 32) != 0 THEN 'TRUNCATE' ELSE NULL END
            ],
            NULL
        ) AS events,
        CASE
            WHEN (tr.tgtype::int & 64) != 0 THEN 'INSTEAD OF'
            WHEN (tr.tgtype::int & 2) != 0 THEN 'BEFORE'
            ELSE 'AFTER'
        END AS action_timing,
        CASE
            WHEN (tr.tgtype::int & 1) != 0 THEN 'ROW'
            ELSE 'STATEMENT'
        END AS orientation,
        pg_get_triggerdef(tr.oid, true) AS action_statement,
        tr.tgenabled != 'D' AS is_enabled
    FROM pg_trigger tr
    JOIN pg_class t ON t.oid = tr.tgrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = ANY(COALESCE(%(schemas)s, ARRAY[%(schema)s]))
      AND NOT tr.tgisinternal
    ORDER BY schema_name, table_name, trigger_name
) t;
