// GET /api/stock -> { product_id: {stock, price} } for the storefront
import { json, ensureSchema } from './_shared.js';

export async function onRequestGet(context) {
  const { env } = context;
  await ensureSchema(env.DB);
  const { results } = await env.DB.prepare('SELECT product_id, stock, price FROM stock').all();
  return json({ ok: true, stock: results || [] });
}
