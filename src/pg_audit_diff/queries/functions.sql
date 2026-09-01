SELECT COALESCE(
    json_object_agg(function_key, json_build_object(
        'function_key', function_key,
        'schema_name', schema_name,
        'function_name', function_name,
        'function_signature', function_signature,
        'return_type', return_type,
        'prokind', prokind,
        'volatility', volatility,
        'is_security_definer', is_security_definer,
        'is_leakproof', is_leakproof,
        'parallel_safety', parallel_safety,
        'definition', definition
    )),
    '{}'::json
) AS functions
FROM (
    SELECT
        n.nspname AS schema_name,
        p.proname AS function_name,
        pg_get_function_identity_arguments(p.oid) AS function_signature,
        format_type(p.prorettype, null) AS return_type,
        p.prokind::text AS prokind,
        p.provolatile::text AS volatility,
        p.prosecdef AS is_security_definer,
        p.proleakproof AS is_leakproof,
        p.proparallel::text AS parallel_safety,
        pg_get_functiondef(p.oid) AS definition,
        CONCAT(n.nspname, '.', p.proname, '(', COALESCE(pg_get_function_identity_arguments(p.oid), ''), ')') AS function_key
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = ANY(COALESCE(%(schemas)s, ARRAY[%(schema)s]))
      AND p.prokind IN ('f', 'p')
    ORDER BY schema_name, function_name, function_signature
) t;
