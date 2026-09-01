SELECT COALESCE(
    json_object_agg(table_key, col_data),
    '{}'::json
) AS columns
FROM (
    SELECT
        CASE WHEN cardinality(COALESCE(%(schemas)s, ARRAY[%(schema)s])::text[]) = 1 THEN t.relname ELSE n.nspname || '.' || t.relname END AS table_key,
        t.relname AS table_name,
        n.nspname AS schema_name,
        json_agg(
            json_build_object(
                'schema_name', n.nspname,
                'table_name', t.relname,
                'column_name', a.attname,
                'ordinal_position', a.attnum,
                'data_type', format_type(a.atttypid, a.atttypmod),
                'is_nullable', NOT a.attnotnull,
                'column_default', CASE
                    WHEN a.attgenerated = '' THEN pg_get_expr(ad.adbin, ad.adrelid)
                    ELSE NULL
                END,
                'is_identity', a.attidentity != '',
                'identity_generation', CASE a.attidentity
                    WHEN 'a' THEN 'ALWAYS'
                    WHEN 'd' THEN 'BY DEFAULT'
                    ELSE NULL
                END,
                'is_generated', a.attgenerated != '',
                'generation_expression', CASE
                    WHEN a.attgenerated != '' THEN pg_get_expr(ad.adbin, ad.adrelid)
                    ELSE NULL
                END,
                'attstorage', CASE a.attstorage
                    WHEN 'p' THEN 'plain'
                    WHEN 'e' THEN 'external'
                    WHEN 'm' THEN 'main'
                    WHEN 'x' THEN 'extended'
                    ELSE a.attstorage::text
                END,
                'attcompression', CASE a.attcompression
                    WHEN 'l' THEN 'lz4'
                    WHEN 'p' THEN 'pglz'
                    ELSE NULL
                END
            )
            ORDER BY a.attnum
        ) AS col_data
    FROM pg_attribute a
    JOIN pg_class t ON t.oid = a.attrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
    WHERE n.nspname = ANY(COALESCE(%(schemas)s, ARRAY[%(schema)s]))
      AND t.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND a.attnum > 0
      AND NOT a.attisdropped
    GROUP BY n.nspname, t.relname
    ORDER BY n.nspname, t.relname
) t;
