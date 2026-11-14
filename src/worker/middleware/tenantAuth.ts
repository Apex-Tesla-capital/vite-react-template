import { Context, Next } from 'hono';
import { createClient } from '@supabase/supabase-js';
import type { SupabaseClient } from '@supabase/supabase-js';

export type TenantRole = 'owner' | 'admin' | 'member';

/** Minimal Supabase schema typing needed by this Worker. */
export type CoreDatabase = {
  public: {
    Tables: {};
    Views: {};
    Functions: {};
    Enums: {};
    CompositeTypes: {};
  };
  core: {
    Tables: {
      settlements: {
        Row: {
          id: string;
          tenant_id: string;
          amount: number;
          status: string;
          created_at: string;
        };
        Insert: {
          id?: string;
          tenant_id: string;
          amount: number;
          status?: string;
          created_at?: string;
        };
        Update: {
          id?: string;
          tenant_id?: string;
          amount?: number;
          status?: string;
          created_at?: string;
        };
        Relationships: [];
      };
    };
    Views: {};
    Functions: {};
    Enums: {};
    CompositeTypes: {};
  };
};

export type TenantEnv = {
  Bindings: {
    SUPABASE_URL: string;
    SUPABASE_ANON_KEY: string;
  };
  Variables: {
    userId: string;
    tenantId: string;
    tenantRole: TenantRole;
    userSupabase: SupabaseClient<CoreDatabase>;
  };
};

const UUID_SHAPE_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ALLOWED_ROLES: readonly string[] = ['owner', 'admin', 'member'];

export async function tenantAuthMiddleware(c: Context<TenantEnv>, next: Next) {
  const authHeader = c.req.header('Authorization');
  if (!authHeader) {
    return c.json({ error: 'Missing authorization header' }, 401);
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer' || !parts[1].trim()) {
    return c.json({ error: 'Malformed authorization header format' }, 401);
  }
  const token = parts[1].trim();

  const verifier = createClient<CoreDatabase>(c.env.SUPABASE_URL, c.env.SUPABASE_ANON_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  const { data: claimsData, error: claimsError } = await verifier.auth.getClaims(token);
  if (claimsError || !claimsData?.claims) {
    return c.json({ error: 'Invalid or expired session token' }, 401);
  }

  const claims = claimsData.claims;
  const rawUserId = claims.sub;
  const rawTenantId = claims.tenant_id;
  const rawTenantRole = claims.tenant_role;

  if (
    typeof rawUserId !== 'string' || !UUID_SHAPE_REGEX.test(rawUserId) ||
    typeof rawTenantId !== 'string' || !UUID_SHAPE_REGEX.test(rawTenantId) ||
    typeof rawTenantRole !== 'string' || !ALLOWED_ROLES.includes(rawTenantRole)
  ) {
    return c.json({ error: 'Forbidden: Invalid or malformed authorization claims' }, 403);
  }

  const userSupabase = createClient<CoreDatabase>(c.env.SUPABASE_URL, c.env.SUPABASE_ANON_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
    global: { headers: { Authorization: `Bearer ${token}` } },
  });

  c.set('userId', rawUserId);
  c.set('tenantId', rawTenantId);
  c.set('tenantRole', rawTenantRole as TenantRole);
  c.set('userSupabase', userSupabase);

  await next();
}
