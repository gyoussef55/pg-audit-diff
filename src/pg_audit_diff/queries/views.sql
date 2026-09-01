SELECT COALESCE(
    json_object_agg(view_name, json_build_object(
        'schema_name', schema_name,
        'view_name', view_name,
        'view_type', view_type,
        'definition', pg_get_viewdef(oid, true),
        'is_populated', is_populated
    )),
    '{}'::json
) AS views
FROM (
    SELECT
        c.oid,
        n.nspname AS schema_name,
        CASE WHEN cardinality(COALESCE(%(schemas)s, ARRAY[%(schema)s])::text[]) = 1 THEN c.relname ELSE n.nspname || '.' || c.relname END AS view_name,
        CASE c.relkind
            WHEN 'v' THEN 'view'
            WHEN 'm' THEN 'materialized_view'
        END AS view_type,
        c.relispopulated AS is_populated
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = ANY(COALESCE(%(schemas)s, ARRAY[%(schema)s]))
      AND c.relkind IN ('v', 'm')
    ORDER BY schema_name, view_name
) t;
