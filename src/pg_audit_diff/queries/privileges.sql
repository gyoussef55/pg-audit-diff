SELECT json_build_object(
    'schema', (
        SELECT json_build_object(
            'object_name', n.nspname,
            'object_type', 'schema',
            'owner', pg_get_userbyid(n.nspowner),
            'acl', COALESCE((
                SELECT json_agg(json_build_object(
                    'grantee', CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
                    'grantor', pg_get_userbyid(a.grantor),
                    'privilege_type', a.privilege_type,
                    'is_grantable', a.is_grantable
                ) ORDER BY a.grantee, a.privilege_type)
                FROM aclexplode(n.nspacl) a
            ), '[]'::json)
        )
        FROM pg_namespace n
        WHERE n.nspname = %(schema)s
    ),
    'tables', COALESCE((
        SELECT json_object_agg(
            c.relname,
            json_build_object(
                'object_name', c.relname,
                'object_type', CASE c.relkind
                    WHEN 'r' THEN 'table'
                    WHEN 'p' THEN 'partitioned_table'
                    WHEN 'v' THEN 'view'
                    WHEN 'm' THEN 'materialized_view'
                    WHEN 'S' THEN 'sequence'
                    WHEN 'f' THEN 'foreign_table'
                    ELSE 'other'
                END,
                'owner', pg_get_userbyid(c.relowner),
                'acl', COALESCE((
                    SELECT json_agg(json_build_object(
                        'grantee', CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
                        'grantor', pg_get_userbyid(a.grantor),
                        'privilege_type', a.privilege_type,
                        'is_grantable', a.is_grantable
                    ) ORDER BY a.grantee, a.privilege_type)
                    FROM aclexplode(c.relacl) a
                ), '[]'::json)
            )
        )
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = %(schema)s
          AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
    ), '{}'::json),
    'routines', COALESCE((
        SELECT json_object_agg(
            CONCAT(p.proname, '(', pg_get_function_identity_arguments(p.oid), ')'),
            json_build_object(
                'object_name', CONCAT(p.proname, '(', pg_get_function_identity_arguments(p.oid), ')'),
                'routine_name', p.proname,
                'signature', pg_get_function_identity_arguments(p.oid),
                'routine_type', CASE p.prokind WHEN 'f' THEN 'function' WHEN 'p' THEN 'procedure' ELSE 'routine' END,
                'owner', pg_get_userbyid(p.proowner),
                'acl', COALESCE((
                    SELECT json_agg(json_build_object(
                        'grantee', CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
                        'grantor', pg_get_userbyid(a.grantor),
                        'privilege_type', a.privilege_type,
                        'is_grantable', a.is_grantable
                    ) ORDER BY a.grantee, a.privilege_type)
                    FROM aclexplode(p.proacl) a
                ), '[]'::json)
            )
        )
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = %(schema)s
          AND p.prokind IN ('f', 'p')
    ), '{}'::json)
) AS privileges;
