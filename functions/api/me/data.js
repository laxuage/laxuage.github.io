// GET  /api/me/data  -> { cart:[{id,qty}], wishlist:[id] } for the logged-in user
// POST /api/me/data  { cart, wishlist } -> saves them (cross-device sync)
import { json, ensureSchema, getSessionUser } from '../_shared.js';

export async function onRequestGet(context) {
  const { request, env } = context;
  await ensureSchema(env.DB);
  const u = await getSessionUser(env, request);
  if (!u) return json({ ok: false, error: 'Not logged in' }, 401);
  const row = await env.DB.prepare('SELECT cart, wishlist FROM user_data WHERE user_id=?').bind(u.id).first();
  let cart = [], wishlist = [];
  if (row) {
    try { cart = JSON.parse(row.cart || '[]'); } catch (e) {}
    try { wishlist = JSON.parse(row.wishlist || '[]'); } catch (e) {}
  }
  return json({ ok: true, cart, wishlist });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  await ensureSchema(env.DB);
  const u = await getSessionUser(env, request);
  if (!u) return json({ ok: false, error: 'Not logged in' }, 401);
  let b;
  try { b = await request.json(); } catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }
  const cart = JSON.stringify(
    (Array.isArray(b.cart) ? b.cart : []).slice(0, 100)
      .map(i => ({ id: parseInt(i.id, 10), qty: Math.max(1, parseInt(i.qty, 10) || 1) }))
      .filter(i => i.id)
  );
  const wishlist = JSON.stringify(
    (Array.isArray(b.wishlist) ? b.wishlist : []).slice(0, 300)
      .map(x => parseInt(x, 10)).filter(Boolean)
  );
  await env.DB.prepare(
    `INSERT INTO user_data (user_id, cart, wishlist, updated_at) VALUES (?,?,?,?)
     ON CONFLICT(user_id) DO UPDATE SET cart=excluded.cart, wishlist=excluded.wishlist, updated_at=excluded.updated_at`
  ).bind(u.id, cart, wishlist, Date.now()).run();
  return json({ ok: true });
}
