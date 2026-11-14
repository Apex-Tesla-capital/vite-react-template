import { describe, expect, it, vi, beforeEach } from 'vitest';
import { Hono } from 'hono';
import { createClient } from '@supabase/supabase-js';
import { tenantAuthMiddleware, TenantEnv } from '../tenantAuth';

vi.mock('@supabase/supabase-js', () => ({
  createClient: vi.fn(),
}));

describe('tenantAuthMiddleware', () => {
  const validUserId = '123e4567-e89b-12d3-a456-426614174000';
  const validTenantId = '987fcdeb-51a2-43d4-8765-426614174fff';
  const mockCreateClient = vi.mocked(createClient);
  let app: Hono<TenantEnv>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockCreateClient.mockImplementation(() => ({
      auth: {
        getClaims: vi.fn().mockResolvedValue({
          data: { claims: { sub: validUserId, tenant_id: validTenantId, tenant_role: 'member' } },
          error: null,
        }),
      },
    }) as ReturnType<typeof createClient>);

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
    mockCreateClient.mockImplementationOnce(() => ({
      auth: { getClaims: vi.fn().mockResolvedValue({ data: null, error: new Error('expired') }) },
    }) as ReturnType<typeof createClient>);

    const response = await app.request('/test', { headers: { Authorization: 'Bearer expired' } });
    expect(response.status).toBe(401);
  });

  it('returns 403 for malformed claims', async () => {
    mockCreateClient.mockImplementationOnce(() => ({
      auth: {
        getClaims: vi.fn().mockResolvedValue({
          data: { claims: { sub: validUserId, tenant_id: 'invalid', tenant_role: 'member' } },
          error: null,
        }),
      },
    }) as ReturnType<typeof createClient>);

    const response = await app.request('/test', { headers: { Authorization: 'Bearer valid' } });
    expect(response.status).toBe(403);
  });

  it('sets tenant context for valid claims', async () => {
    const response = await app.request('/test', { headers: { Authorization: 'Bearer valid' } });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ userId: validUserId, tenantId: validTenantId, tenantRole: 'member' });
  });
});
