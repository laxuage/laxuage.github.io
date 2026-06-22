// GET  /api/admin/products            -> all products (incl. inactive)
// POST /api/admin/products            -> create or update (if id present) a product
// POST /api/admin/products {action:'delete', id} -> delete
import { json, ensureSchema, seedProductsIfEmpty, rowToProduct } from '../_shared.js';

export async function onRequestGet(context) {
  const { env } = context;
  await ensureSchema(env.DB);
  await seedProductsIfEmpty(env.DB);
  const { results } = await env.DB
    .prepare('SELECT * FROM products ORDER BY sort_order ASC, id ASC')
    .all();
  const products = (results || []).map(r => {
    const p = rowToProduct(r);
    p.active = r.active;
    return p;
  });
  return json({ ok: true, products });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  await ensureSchema(env.DB);
  let b;
  try { b = await request.json(); } catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }

  if (b.action === 'delete') {
    const id = parseInt(b.id, 10);
    if (!id) return json({ ok: false, error: 'Invalid id' }, 400);
    await env.DB.prepare('DELETE FROM products WHERE id=?').bind(id).run();
    return json({ ok: true });
  }

  const name = String(b.name || '').trim().slice(0, 120);
  if (!name) return json({ ok: false, error: 'Name is required' }, 400);
  const price = parseInt(b.price, 10) || 0;
  const mrp = parseInt(b.mrp, 10) || price;
  const description = String(b.description || '').slice(0, 2000);
  const category = String(b.category || 'handbag').slice(0, 40);
  const material = String(b.material || '').slice(0, 60);
  const weight_g = parseInt(b.weight_g, 10) || null;
  const size = String(b.size || '').slice(0, 80);
  const badge = String(b.badge || '').slice(0, 20);
  const rating = b.rating != null ? Number(b.rating) : 4.6;
  const reviews = parseInt(b.reviews, 10) || 0;
  const stock = (b.stock === '' || b.stock == null) ? null : Math.max(0, parseInt(b.stock, 10) || 0);
  const active = (b.active === 0 || b.active === false) ? 0 : 1;
  const images = JSON.stringify(Array.isArray(b.images) ? b.images.slice(0, 8) : []);
  // Colour variants: up to 8, each { name, image }.
  const colorsArr = Array.isArray(b.colors)
    ? b.colors
        .filter(c => c && typeof c === 'object' && (c.name || c.image))
        .slice(0, 8)
        .map(c => ({ name: String(c.name || '').slice(0, 40), image: String(c.image || '').slice(0, 400) }))
    : [];
  const colors = JSON.stringify(colorsArr);
  const color = String(b.color || (colorsArr[0] && colorsArr[0].name) || '').slice(0, 40);
  const id = parseInt(b.id, 10);

  if (id) {
    await env.DB.prepare(
      `UPDATE products SET name=?, price=?, mrp=?, description=?, category=?, material=?, color=?, weight_g=?, size=?, badge=?, rating=?, reviews=?, stock=?, images=?, colors=?, active=? WHERE id=?`
    ).bind(name, price, mrp, description, category, material, color, weight_g, size, badge, rating, reviews, stock, images, colors, active, id).run();
    return json({ ok: true, id });
  } else {
    const res = await env.DB.prepare(
      `INSERT INTO products (name,price,mrp,description,category,material,color,weight_g,size,badge,rating,reviews,stock,images,colors,active,sort_order,created_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(name, price, mrp, description, category, material, color, weight_g, size, badge, rating, reviews, stock, images, colors, active, 999, Date.now()).run();
    return json({ ok: true, id: res.meta && res.meta.last_row_id });
  }
}
