SELECT COALESCE(
    json_object_agg(extension_name, json_build_object(
        'extension_name', extension_name,
        'version', version,
        'schema', schema,
        'relocatable', relocatable,
        'description', description
    )),
    '{}'::json
) AS extensions
FROM (
    SELECT 
        e.extname AS extension_name,
        e.extversion AS version,
        n.nspname AS schema,
        e.extrelocatable AS relocatable,
        c.description
    FROM pg_extension e
    LEFT JOIN pg_namespace n ON n.oid = e.extnamespace
    LEFT JOIN pg_description c ON c.objoid = e.oid AND c.objsubid = 0
    WHERE e.extname != 'plpgsql'
    ORDER BY e.extname
) t;
