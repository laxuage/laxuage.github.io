// GET /api/products -> active products for the storefront (seeded on first call)
import { json, ensureSchema, seedProductsIfEmpty, rowToProduct } from './_shared.js';

export async function onRequestGet(context) {
  const { env } = context;
  await ensureSchema(env.DB);
  await seedProductsIfEmpty(env.DB);
  const { results } = await env.DB
    .prepare('SELECT * FROM products WHERE active=1 ORDER BY sort_order ASC, id ASC')
    .all();
  return json({ ok: true, products: (results || []).map(rowToProduct) });
}
