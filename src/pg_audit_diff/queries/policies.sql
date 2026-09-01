SELECT COALESCE(
    json_object_agg(policy_key, json_build_object(
        'schema_name', schema_name,
        'table_name', table_name,
        'policy_name', policy_name,
        'command', command,
        'roles', roles,
        'is_permissive', is_permissive,
        'using_expression', using_expression,
        'check_expression', check_expression
    )),
    '{}'::json
) AS policies
FROM (
    SELECT
        n.nspname AS schema_name,
        CASE WHEN cardinality(COALESCE(%(schemas)s, ARRAY[%(schema)s])::text[]) = 1 THEN t.relname ELSE n.nspname || '.' || t.relname END AS table_name,
        p.polname AS policy_name,
        CONCAT(CASE WHEN cardinality(COALESCE(%(schemas)s, ARRAY[%(schema)s])::text[]) = 1 THEN t.relname ELSE n.nspname || '.' || t.relname END, '.', p.polname) AS policy_key,
        CASE p.polcmd
            WHEN '*' THEN 'ALL'
            WHEN 'r' THEN 'SELECT'
            WHEN 'a' THEN 'INSERT'
            WHEN 'w' THEN 'UPDATE'
            WHEN 'd' THEN 'DELETE'
            ELSE 'ALL'
        END AS command,
        CASE
            WHEN p.polroles = '{0}' THEN ARRAY['PUBLIC']
            ELSE ARRAY(
                SELECT COALESCE(r.rolname, 'PUBLIC')
                FROM unnest(p.polroles) AS role_oid
                LEFT JOIN pg_roles r ON r.oid = role_oid
            )
        END AS roles,
        p.polpermissive AS is_permissive,
        pg_get_expr(p.polqual, p.polrelid) AS using_expression,
        pg_get_expr(p.polwithcheck, p.polrelid) AS check_expression
    FROM pg_policy p
    JOIN pg_class t ON t.oid = p.polrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = ANY(COALESCE(%(schemas)s, ARRAY[%(schema)s]))
    ORDER BY schema_name, table_name, policy_name
) pol;
