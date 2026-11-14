-- Apex Capital: core multi-tenant schema and settlement authorization
CREATE SCHEMA IF NOT EXISTS core;

CREATE TABLE IF NOT EXISTS core.tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS core.tenant_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES core.tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS core.user_sessions (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    active_tenant_id UUID NOT NULL REFERENCES core.tenants(id) ON DELETE CASCADE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS core.settlements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES core.tenants(id) ON DELETE CASCADE,
    amount NUMERIC(15, 2) NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE core.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.tenant_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.settlements ENABLE ROW LEVEL SECURITY;

ALTER TABLE core.tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE core.tenant_memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE core.user_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE core.settlements FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS user_sessions_self_select ON core.user_sessions;
CREATE POLICY user_sessions_self_select ON core.user_sessions
    FOR SELECT TO authenticated
    USING (user_id = auth.uid());

DROP POLICY IF EXISTS tenant_memberships_self_select ON core.tenant_memberships;
CREATE POLICY tenant_memberships_self_select ON core.tenant_memberships
    FOR SELECT TO authenticated
    USING (user_id = auth.uid());

CREATE OR REPLACE FUNCTION core.get_active_tenant_id()
RETURNS UUID
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT active_tenant_id
    FROM core.user_sessions
    WHERE user_id = auth.uid();
$$;

CREATE OR REPLACE FUNCTION core.check_tenant_access(p_tenant_id UUID, p_min_role TEXT DEFAULT 'member')
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_role TEXT;
BEGIN
    IF auth.uid() IS NULL OR p_tenant_id IS NULL THEN
        RETURN FALSE;
    END IF;

    SELECT role INTO v_role
    FROM core.tenant_memberships
    WHERE tenant_id = p_tenant_id
      AND user_id = auth.uid();

    IF v_role IS NULL THEN
        RETURN FALSE;
    END IF;

    IF p_min_role = 'member' THEN
        RETURN v_role IN ('owner', 'admin', 'member');
    ELSIF p_min_role = 'admin' THEN
        RETURN v_role IN ('owner', 'admin');
    ELSIF p_min_role = 'owner' THEN
        RETURN v_role = 'owner';
    END IF;

    RETURN FALSE;
END;
$$;

CREATE OR REPLACE FUNCTION core.current_tenant_id()
RETURNS UUID
LANGUAGE sql
STABLE
AS $$
    SELECT NULLIF(current_setting('request.jwt.claim.tenant_id', true), '')::UUID;
$$;

REVOKE EXECUTE ON FUNCTION core.get_active_tenant_id() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION core.get_active_tenant_id() TO authenticated;
REVOKE EXECUTE ON FUNCTION core.check_tenant_access(UUID, TEXT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION core.check_tenant_access(UUID, TEXT) TO authenticated;

CREATE OR REPLACE FUNCTION core.custom_access_token_hook(event JSONB)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_user_id UUID;
    v_claims JSONB;
    v_tenant_id UUID;
    v_role TEXT;
BEGIN
    v_user_id := NULLIF(event->>'user_id', '')::UUID;
    v_claims := COALESCE(event->'claims', '{}'::JSONB);

    IF v_user_id IS NULL THEN
        RETURN jsonb_build_object('claims', v_claims - 'tenant_id' - 'tenant_role');
    END IF;

    SELECT s.active_tenant_id, tm.role
      INTO v_tenant_id, v_role
      FROM core.user_sessions s
      INNER JOIN core.tenant_memberships tm
        ON tm.user_id = s.user_id
       AND tm.tenant_id = s.active_tenant_id
     WHERE s.user_id = v_user_id
     LIMIT 1;

    IF v_tenant_id IS NOT NULL AND v_role IS NOT NULL THEN
        v_claims := jsonb_set(v_claims, '{tenant_id}', to_jsonb(v_tenant_id));
        v_claims := jsonb_set(v_claims, '{tenant_role}', to_jsonb(v_role));
    ELSE
        v_claims := v_claims - 'tenant_id' - 'tenant_role';
    END IF;

    RETURN jsonb_build_object('claims', v_claims);
END;
$$;

GRANT USAGE ON SCHEMA core TO supabase_auth_admin, authenticated;
GRANT SELECT ON core.user_sessions, core.tenant_memberships TO supabase_auth_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON core.settlements TO authenticated;
REVOKE EXECUTE ON FUNCTION core.custom_access_token_hook(JSONB) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION core.custom_access_token_hook(JSONB) TO supabase_auth_admin;

DO $$
DECLARE
    pol RECORD;
BEGIN
    FOR pol IN
        SELECT policyname
        FROM pg_policies
        WHERE schemaname = 'core' AND tablename = 'settlements'
    LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON core.settlements', pol.policyname);
    END LOOP;
END $$;

CREATE POLICY settlements_member_select ON core.settlements
    FOR SELECT TO authenticated
    USING (
        tenant_id = core.current_tenant_id()
        AND tenant_id = core.get_active_tenant_id()
        AND core.check_tenant_access(tenant_id, 'member')
    );

CREATE POLICY settlements_admin_insert ON core.settlements
    FOR INSERT TO authenticated
    WITH CHECK (
        tenant_id = core.current_tenant_id()
        AND tenant_id = core.get_active_tenant_id()
        AND core.check_tenant_access(tenant_id, 'admin')
    );

CREATE POLICY settlements_admin_update ON core.settlements
    FOR UPDATE TO authenticated
    USING (
        tenant_id = core.current_tenant_id()
        AND tenant_id = core.get_active_tenant_id()
        AND core.check_tenant_access(tenant_id, 'admin')
    )
    WITH CHECK (
        tenant_id = core.current_tenant_id()
        AND tenant_id = core.get_active_tenant_id()
        AND core.check_tenant_access(tenant_id, 'admin')
    );

CREATE POLICY settlements_admin_delete ON core.settlements
    FOR DELETE TO authenticated
    USING (
        tenant_id = core.current_tenant_id()
        AND tenant_id = core.get_active_tenant_id()
        AND core.check_tenant_access(tenant_id, 'admin')
    );
