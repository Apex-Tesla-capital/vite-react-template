import { Hono } from 'hono';
import { tenantAuthMiddleware, TenantEnv } from './middleware/tenantAuth';

const app = new Hono<TenantEnv>();

app.get('/api/', (c) => c.json({ name: 'Cloudflare' }));

const tenantApi = new Hono<TenantEnv>();
tenantApi.use('*', tenantAuthMiddleware);

tenantApi.get('/settlements', async (c) => {
  const tenantId = c.get('tenantId');
  const userId = c.get('userId');
  const userSupabase = c.get('userSupabase');

  const { data, error } = await userSupabase
    .schema('core')
    .from('settlements')
    .select('*')
    .eq('tenant_id', tenantId);

  if (error) {
    console.error('[settlements:query_failed]', {
      userId,
      tenantId,
      code: error.code,
      message: error.message,
    });
    return c.json({ error: 'Unable to retrieve settlements' }, 500);
  }

  return c.json({ success: true, tenantId, userId, settlements: data });
});

app.route('/api/v1', tenantApi);

export default app;
