WITH filtered_tables AS (
    SELECT
        t.oid AS table_oid,
        t.relname AS rel_table_name,
        n.nspname AS schema_name,
        CASE WHEN cardinality(COALESCE(%(schemas)s, ARRAY[%(schema)s])::text[]) = 1 THEN t.relname ELSE n.nspname || '.' || t.relname END AS table_name
    FROM pg_class t
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = ANY(COALESCE(%(schemas)s, ARRAY[%(schema)s]))
      AND t.relkind IN ('r', 'p', 'm')
),
index_columns AS (
    SELECT
        t.schema_name,
        t.table_name,
        i.relname AS index_name,
        am.amname AS am_name,
        ix.indisunique AS is_unique,
        ix.indisprimary AS is_primary,
        ix.indisvalid AS is_valid,
        ix.indisready AS is_ready,
        ix.indisclustered AS is_clustered,
        c.conname AS constraint_name,
        ts.spcname AS tablespace,
        i.reloptions AS reloptions,
        CASE i.relpersistence
            WHEN 'u' THEN 'unlogged'
            WHEN 't' THEN 'temporary'
            ELSE 'permanent'
        END AS persistence,
        COALESCE(
            ARRAY_AGG(
                COALESCE(a.attname, pg_get_indexdef(i.oid, x.ordinality::int, true))
                ORDER BY x.ordinality
            ) FILTER (WHERE x.ordinality <= ix.indnkeyatts),
            '{}'
        ) AS columns,
        COALESCE(
            ARRAY_AGG(
                COALESCE(a.attname, pg_get_indexdef(i.oid, x.ordinality::int, true))
                ORDER BY x.ordinality
            ) FILTER (WHERE x.ordinality > ix.indnkeyatts),
            '{}'
        ) AS include_columns,
        COALESCE(
            ARRAY_AGG(
                COALESCE(a.attname, pg_get_indexdef(i.oid, x.ordinality::int, true))
                || ':' || COALESCE(opc.opcname, '')
                || ':' || CASE
                    WHEN (ix.indoption[x.ordinality - 1] & 1) != 0 THEN 'desc'
                    ELSE 'asc'
                END
                || ':' || CASE
                    WHEN (ix.indoption[x.ordinality - 1] & 2) != 0 THEN 'nulls_first'
                    ELSE 'nulls_last'
                END
                || ':' || COALESCE(coll.collname, '')
                ORDER BY x.ordinality
            ) FILTER (WHERE x.ordinality <= ix.indnkeyatts),
            '{}'
        ) AS column_details,
        pg_get_expr(ix.indpred, ix.indrelid) AS predicate
    FROM filtered_tables t
    JOIN pg_index ix ON t.table_oid = ix.indrelid
    JOIN pg_class i ON i.oid = ix.indexrelid
    JOIN pg_am am ON am.oid = i.relam
    LEFT JOIN pg_tablespace ts ON ts.oid = i.reltablespace
    LEFT JOIN pg_constraint c ON c.conindid = ix.indexrelid
    LEFT JOIN unnest(ix.indkey) WITH ORDINALITY AS x(attnum, ordinality) ON true
    LEFT JOIN pg_attribute a
        ON a.attrelid = t.table_oid
       AND a.attnum = x.attnum
    LEFT JOIN pg_opclass opc ON opc.oid = ix.indclass[x.ordinality - 1]
    LEFT JOIN pg_collation coll ON coll.oid = ix.indcollation[x.ordinality - 1]
    GROUP BY
        t.schema_name,
        t.table_name,
        i.relname,
        am.amname,
        ix.indisunique,
        ix.indisprimary,
        ix.indisvalid,
        ix.indisready,
        ix.indisclustered,
        c.conname,
        ts.spcname,
        i.reloptions,
        i.relpersistence,
        ix.indoption,
        ix.indpred,
        ix.indrelid,
        i.oid,
        ix.indnkeyatts
    ORDER BY t.schema_name, t.table_name, i.relname
)
SELECT COALESCE(
    json_agg(
        json_build_object(
            'schema_name', schema_name,
            'table_name', table_name,
            'index_name', index_name,
            'am_name', am_name,
            'is_unique', is_unique,
            'is_primary', is_primary,
            'is_valid', is_valid,
            'is_ready', is_ready,
            'is_clustered', is_clustered,
            'constraint_name', constraint_name,
            'tablespace', tablespace,
            'reloptions', reloptions,
            'persistence', persistence,
            'columns', columns,
            'include_columns', include_columns,
            'column_details', column_details,
            'predicate', predicate
        )
    ),
    '[]'::json
) AS indexes
FROM index_columns;
