// GET  /api/admin/orders            -> list recent orders
// POST /api/admin/orders { id, status } -> update an order's status
import { json, ensureSchema } from '../_shared.js';

const STATUSES = ['new', 'confirmed', 'shipped', 'delivered', 'cancelled'];

export async function onRequestGet(context) {
  const { env } = context;
  await ensureSchema(env.DB);
  const { results } = await env.DB
    .prepare('SELECT * FROM orders ORDER BY created_at DESC LIMIT 300')
    .all();
  return json({ ok: true, orders: results || [] });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  await ensureSchema(env.DB);
  let b;
  try { b = await request.json(); } catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }
  const id = String(b.id || '');
  const status = String(b.status || '');
  if (!id || STATUSES.indexOf(status) < 0) return json({ ok: false, error: 'Invalid' }, 400);
  await env.DB.prepare('UPDATE orders SET status=? WHERE id=?').bind(status, id).run();
  return json({ ok: true });
}
