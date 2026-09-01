SELECT COALESCE(
    json_object_agg(sequence_name, json_build_object(
        'schema_name', schema_name,
        'sequence_name', sequence_name,
        'data_type', data_type,
        'start_value', start_value,
        'min_value', min_value,
        'max_value', max_value,
        'increment_by', increment_by,
        'cycle', cycle,
        'cache_size', cache_size,
        'owned_by_table', owned_by_table,
        'owned_by_column', owned_by_column
    )),
    '{}'::json
) AS sequences
FROM (
    SELECT
        n.nspname AS schema_name,
        CASE WHEN cardinality(COALESCE(%(schemas)s, ARRAY[%(schema)s])::text[]) = 1 THEN c.relname ELSE n.nspname || '.' || c.relname END AS sequence_name,
        format_type(s.seqtypid, null) AS data_type,
        s.seqstart AS start_value,
        s.seqmin AS min_value,
        s.seqmax AS max_value,
        s.seqincrement AS increment_by,
        s.seqcycle AS cycle,
        s.seqcache AS cache_size,
        tbl.relname AS owned_by_table,
        a.attname AS owned_by_column
    FROM pg_sequence s
    JOIN pg_class c ON c.oid = s.seqrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    LEFT JOIN pg_depend d
        ON d.classid = 'pg_class'::regclass
       AND d.objid = s.seqrelid
       AND d.deptype IN ('a', 'i')
       AND d.refclassid = 'pg_class'::regclass
       AND d.refobjsubid > 0
    LEFT JOIN pg_class tbl ON tbl.oid = d.refobjid
    LEFT JOIN pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid
    WHERE n.nspname = ANY(COALESCE(%(schemas)s, ARRAY[%(schema)s]))
      AND c.relkind = 'S'
    ORDER BY schema_name, sequence_name
) t;
