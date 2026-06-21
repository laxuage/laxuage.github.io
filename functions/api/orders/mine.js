// GET /api/orders/mine -> the logged-in customer's own orders (cross-device)
import { json, ensureSchema, getSessionUser } from '../_shared.js';

export async function onRequestGet(context) {
  const { request, env } = context;
  await ensureSchema(env.DB);
  const user = await getSessionUser(env, request);
  if (!user) return json({ ok: false, error: 'Not logged in' }, 401);
  const { results } = await env.DB
    .prepare('SELECT id, created_at, items, subtotal, shipping, total, payment_method, payment_status, status FROM orders WHERE customer_email=? ORDER BY created_at DESC LIMIT 100')
    .bind(user.email)
    .all();
  return json({ ok: true, orders: results || [] });
}
