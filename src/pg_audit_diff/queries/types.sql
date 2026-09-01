WITH enum_types AS (
    SELECT
        n.nspname AS schema_name,
        CASE WHEN cardinality(COALESCE(%(schemas)s, ARRAY[%(schema)s])::text[]) = 1 THEN t.typname ELSE n.nspname || '.' || t.typname END AS type_name,
        'enum' AS type_kind,
        COALESCE(
            ARRAY_AGG(e.enumlabel ORDER BY e.enumsortorder),
            '{}'
        ) AS enum_values,
        NULL::text AS base_type,
        NULL::text[] AS attributes,
        NULL::boolean AS is_nullable,
        NULL::text AS domain_default,
        NULL::text[] AS constraints
    FROM pg_type t
    JOIN pg_namespace n ON n.oid = t.typnamespace
    LEFT JOIN pg_enum e ON e.enumtypid = t.oid
    WHERE n.nspname = ANY(COALESCE(%(schemas)s, ARRAY[%(schema)s]))
      AND t.typtype = 'e'
    GROUP BY n.nspname, t.typname
),
domain_types AS (
    SELECT
        n.nspname AS schema_name,
        CASE WHEN cardinality(COALESCE(%(schemas)s, ARRAY[%(schema)s])::text[]) = 1 THEN t.typname ELSE n.nspname || '.' || t.typname END AS type_name,
        'domain' AS type_kind,
        '{}'::text[] AS enum_values,
        format_type(t.typbasetype, t.typtypmod) AS base_type,
        NULL::text[] AS attributes,
        NOT t.typnotnull AS is_nullable,
        t.typdefault AS domain_default,
        COALESCE((
            SELECT ARRAY_AGG(pg_get_constraintdef(dc.oid) ORDER BY dc.conname)
            FROM pg_constraint dc
            WHERE dc.contypid = t.oid
        ), '{}'::text[]) AS constraints
    FROM pg_type t
    JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE n.nspname = ANY(COALESCE(%(schemas)s, ARRAY[%(schema)s]))
      AND t.typtype = 'd'
),
composite_types AS (
    SELECT
        n.nspname AS schema_name,
        CASE WHEN cardinality(COALESCE(%(schemas)s, ARRAY[%(schema)s])::text[]) = 1 THEN t.typname ELSE n.nspname || '.' || t.typname END AS type_name,
        'composite' AS type_kind,
        '{}'::text[] AS enum_values,
        NULL::text AS base_type,
        COALESCE(
            ARRAY_AGG(a.attname || ' ' || format_type(a.atttypid, a.atttypmod) ORDER BY a.attnum),
            '{}'
        ) AS attributes,
        NULL::boolean AS is_nullable,
        NULL::text AS domain_default,
        NULL::text[] AS constraints
    FROM pg_type t
    JOIN pg_namespace n ON n.oid = t.typnamespace
    JOIN pg_class c ON c.oid = t.typrelid AND c.relkind = 'c'
    LEFT JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
    WHERE n.nspname = ANY(COALESCE(%(schemas)s, ARRAY[%(schema)s]))
      AND t.typtype = 'c'
    GROUP BY n.nspname, t.typname
),
all_types AS (
    SELECT * FROM enum_types
    UNION ALL
    SELECT * FROM domain_types
    UNION ALL
    SELECT * FROM composite_types
)
SELECT COALESCE(
    json_object_agg(type_name, json_build_object(
        'schema_name', schema_name,
        'type_name', type_name,
        'type_kind', type_kind,
        'enum_values', enum_values,
        'base_type', base_type,
        'attributes', attributes,
        'is_nullable', is_nullable,
        'domain_default', domain_default,
        'constraints', constraints
    )),
    '{}'::json
) AS types
FROM all_types;
