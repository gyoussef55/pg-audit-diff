SELECT COALESCE(
    json_object_agg(
        id::text,
        json_build_object(
            'id', id,
            'timestamp', timestamp,
            'name', name
        )
    ),
    '{}'::json
) AS migrations
FROM (
    SELECT
        id,
        timestamp,
        name
    FROM {migrations_schema}.{migrations_table}
    ORDER BY id
) t;
