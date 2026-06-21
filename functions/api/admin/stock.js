// GET  /api/admin/stock                         -> all stock/price overrides
// POST /api/admin/stock { product_id, stock, price } -> upsert one product
import { json, ensureSchema } from '../_shared.js';

export async function onRequestGet(context) {
  const { env } = context;
  await ensureSchema(env.DB);
  const { results } = await env.DB.prepare('SELECT * FROM stock').all();
  return json({ ok: true, stock: results || [] });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  await ensureSchema(env.DB);
  let b;
  try { b = await request.json(); } catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }
  const pid = parseInt(b.product_id, 10);
  if (!pid) return json({ ok: false, error: 'Invalid product' }, 400);
  const stock = Math.max(0, parseInt(b.stock, 10) || 0);
  const price = (b.price !== null && b.price !== undefined && b.price !== '') ? parseInt(b.price, 10) : null;
  await env.DB.prepare(
    `INSERT INTO stock (product_id, stock, price, updated_at) VALUES (?,?,?,?)
     ON CONFLICT(product_id) DO UPDATE SET stock=excluded.stock, price=excluded.price, updated_at=excluded.updated_at`
  ).bind(pid, stock, price, Date.now()).run();
  return json({ ok: true });
}
