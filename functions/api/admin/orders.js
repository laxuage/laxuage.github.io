// GET  /api/admin/orders            -> list recent orders
// POST /api/admin/orders { id, status?, courier?, tracking_no? } -> update an order
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
  if (!id) return json({ ok: false, error: 'Missing order id' }, 400);

  // Build the update from whichever fields were provided (status / courier / tracking).
  const sets = [], vals = [];
  if (b.status != null) {
    const status = String(b.status);
    if (STATUSES.indexOf(status) < 0) return json({ ok: false, error: 'Invalid status' }, 400);
    sets.push('status=?'); vals.push(status);
  }
  if (b.courier != null) { sets.push('courier=?'); vals.push(String(b.courier).slice(0, 60)); }
  if (b.tracking_no != null) { sets.push('tracking_no=?'); vals.push(String(b.tracking_no).trim().slice(0, 80)); }
  if (!sets.length) return json({ ok: false, error: 'Nothing to update' }, 400);

  vals.push(id);
  await env.DB.prepare('UPDATE orders SET ' + sets.join(', ') + ' WHERE id=?').bind(...vals).run();
  return json({ ok: true });
}
