import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Hono } from 'hono';
import { createClient } from '@supabase/supabase-js';
import type { SupabaseClient } from '@supabase/supabase-js';
import { tenantAuthMiddleware, TenantEnv } from '../tenantAuth';
import type { CoreDatabase } from '../tenantAuth';

vi.mock('@supabase/supabase-js', () => ({
  createClient: vi.fn(),
}));

type MockSupabaseClient = {
  auth: {
    getClaims: ReturnType<typeof vi.fn>;
  };
};

const validUserId = '123e4567-e89b-12d3-a456-426614174000';
const validTenantId = '987fcdeb-51a2-43d4-8765-426614174fff';
const testBindings = {
  SUPABASE_URL: 'https://example.supabase.co',
  SUPABASE_ANON_KEY: 'test-anon-key',
};

describe('tenantAuthMiddleware', () => {
  const mockCreateClient = vi.mocked(createClient);
  let app: Hono<TenantEnv>;
  let mockSupabaseInstance: MockSupabaseClient;

  beforeEach(() => {
    vi.clearAllMocks();
    mockSupabaseInstance = { auth: { getClaims: vi.fn() } };
    mockCreateClient.mockImplementation(
      () => mockSupabaseInstance as unknown as SupabaseClient<CoreDatabase, 'core'>,
    );

    app = new Hono<TenantEnv>();
    app.use('*', tenantAuthMiddleware);
    app.get('/test', (c) => c.json({
      userId: c.get('userId'),
      tenantId: c.get('tenantId'),
      tenantRole: c.get('tenantRole'),
    }));
  });

  it('returns 401 when the authorization header is missing', async () => {
    const response = await app.request('/test');
    expect(response.status).toBe(401);
  });

  it('returns 401 when token verification fails', async () => {
    mockSupabaseInstance.auth.getClaims.mockResolvedValueOnce({
      data: null,
      error: { message: 'Token expired' },
    });

    const response = await app.request('/test', {
      headers: { Authorization: 'Bearer expired_token' },
    }, testBindings);
    expect(response.status).toBe(401);
  });

  it('returns 403 when claims fail validation', async () => {
    mockSupabaseInstance.auth.getClaims.mockResolvedValueOnce({
      data: {
        claims: {
          sub: validUserId,
          tenant_id: 'not-a-uuid',
          tenant_role: 'member',
        },
      },
      error: null,
    });

    const response = await app.request('/test', {
      headers: { Authorization: 'Bearer invalid_uuid_token' },
    }, testBindings);
    expect(response.status).toBe(403);
  });

  it('sets context variables when claims are valid', async () => {
    mockSupabaseInstance.auth.getClaims.mockResolvedValueOnce({
      data: {
        claims: {
          sub: validUserId,
          tenant_id: validTenantId,
          tenant_role: 'member',
        },
      },
      error: null,
    });

    const response = await app.request('/test', {
      headers: { Authorization: 'Bearer valid_jwt' },
    }, testBindings);

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      userId: validUserId,
      tenantId: validTenantId,
      tenantRole: 'member',
    });
  });
});
