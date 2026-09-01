SELECT COALESCE(
    json_object_agg(
        target_key,
        json_build_object(
            'schema_name', schema_name,
            'object_type', object_type,
            'object_name', object_name,
            'sub_object_name', sub_object_name,
            'comment', comment
        )
    ),
    '{}'::json
) AS comments
FROM (
    -- Schema comments (pg_shdescription for shared objects or pg_description depending on OID catalog)
    SELECT
        n.nspname AS schema_name,
        'schema' AS object_type,
        n.nspname AS object_name,
        NULL::text AS sub_object_name,
        d.description AS comment,
        CASE WHEN cardinality(COALESCE(%(schemas)s, ARRAY[%(schema)s])::text[]) = 1
             THEN 'schema:' || n.nspname
             ELSE 'schema:' || n.nspname
        END AS target_key
    FROM pg_namespace n
    JOIN pg_description d ON d.objoid = n.oid AND d.classoid = 'pg_namespace'::regclass::oid AND d.objsubid = 0
    WHERE n.nspname = ANY(COALESCE(%(schemas)s, ARRAY[%(schema)s]))

    UNION ALL

    -- Table / View / Matview / Sequence comments
    SELECT
        n.nspname AS schema_name,
        CASE c.relkind
            WHEN 'r' THEN 'table'
            WHEN 'p' THEN 'partitioned_table'
            WHEN 'v' THEN 'view'
            WHEN 'm' THEN 'materialized_view'
            WHEN 'S' THEN 'sequence'
            WHEN 'f' THEN 'foreign_table'
            ELSE 'table'
        END AS object_type,
        c.relname AS object_name,
        NULL::text AS sub_object_name,
        d.description AS comment,
        CASE WHEN cardinality(COALESCE(%(schemas)s, ARRAY[%(schema)s])::text[]) = 1
             THEN 'table:' || c.relname
             ELSE 'table:' || n.nspname || '.' || c.relname
        END AS target_key
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_description d ON d.objoid = c.oid AND d.classoid = 'pg_class'::regclass::oid AND d.objsubid = 0
    WHERE n.nspname = ANY(COALESCE(%(schemas)s, ARRAY[%(schema)s]))
      AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')

    UNION ALL

    -- Column comments
    SELECT
        n.nspname AS schema_name,
        'column' AS object_type,
        c.relname AS object_name,
        a.attname AS sub_object_name,
        d.description AS comment,
        CASE WHEN cardinality(COALESCE(%(schemas)s, ARRAY[%(schema)s])::text[]) = 1
             THEN 'column:' || c.relname || '.' || a.attname
             ELSE 'column:' || n.nspname || '.' || c.relname || '.' || a.attname
        END AS target_key
    FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_description d ON d.objoid = c.oid AND d.classoid = 'pg_class'::regclass::oid AND d.objsubid = a.attnum
    WHERE n.nspname = ANY(COALESCE(%(schemas)s, ARRAY[%(schema)s]))
      AND a.attnum > 0 AND NOT a.attisdropped
      AND c.relkind IN ('r', 'p', 'v', 'm', 'f')

    UNION ALL

    -- Function / Procedure comments
    SELECT
        n.nspname AS schema_name,
        CASE p.prokind WHEN 'f' THEN 'function' WHEN 'p' THEN 'procedure' ELSE 'routine' END AS object_type,
        CONCAT(p.proname, '(', pg_get_function_identity_arguments(p.oid), ')') AS object_name,
        NULL::text AS sub_object_name,
        d.description AS comment,
        CASE WHEN cardinality(COALESCE(%(schemas)s, ARRAY[%(schema)s])::text[]) = 1
             THEN 'function:' || CONCAT(p.proname, '(', pg_get_function_identity_arguments(p.oid), ')')
             ELSE 'function:' || n.nspname || '.' || CONCAT(p.proname, '(', pg_get_function_identity_arguments(p.oid), ')')
        END AS target_key
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    JOIN pg_description d ON d.objoid = p.oid AND d.classoid = 'pg_proc'::regclass::oid AND d.objsubid = 0
    WHERE n.nspname = ANY(COALESCE(%(schemas)s, ARRAY[%(schema)s]))
      AND p.prokind IN ('f', 'p')

    UNION ALL

    -- Type comments
    SELECT
        n.nspname AS schema_name,
        'type' AS object_type,
        t.typname AS object_name,
        NULL::text AS sub_object_name,
        d.description AS comment,
        CASE WHEN cardinality(COALESCE(%(schemas)s, ARRAY[%(schema)s])::text[]) = 1
             THEN 'type:' || t.typname
             ELSE 'type:' || n.nspname || '.' || t.typname
        END AS target_key
    FROM pg_type t
    JOIN pg_namespace n ON n.oid = t.typnamespace
    JOIN pg_description d ON d.objoid = t.oid AND d.classoid = 'pg_type'::regclass::oid AND d.objsubid = 0
    WHERE n.nspname = ANY(COALESCE(%(schemas)s, ARRAY[%(schema)s]))
      AND t.typtype IN ('e', 'd', 'c')

    UNION ALL

    -- Constraint comments
    SELECT
        n.nspname AS schema_name,
        'constraint' AS object_type,
        con.conname AS object_name,
        NULL::text AS sub_object_name,
        d.description AS comment,
        CASE WHEN cardinality(COALESCE(%(schemas)s, ARRAY[%(schema)s])::text[]) = 1
             THEN 'constraint:' || con.conname
             ELSE 'constraint:' || n.nspname || '.' || con.conname
        END AS target_key
    FROM pg_constraint con
    JOIN pg_namespace n ON n.oid = con.connamespace
    JOIN pg_description d ON d.objoid = con.oid AND d.classoid = 'pg_constraint'::regclass::oid AND d.objsubid = 0
    WHERE n.nspname = ANY(COALESCE(%(schemas)s, ARRAY[%(schema)s]))
) comments_all;
