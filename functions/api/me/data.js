// GET  /api/me/data  -> { cart:[{id,qty}], wishlist:[id], addresses:[...] }
// POST /api/me/data  { cart, wishlist, addresses } -> saves them (cross-device sync)
import { json, ensureSchema, getSessionUser } from '../_shared.js';

// Shipping addresses are keyed to the account, not the browser. They used to
// live only in localStorage under a key built from phone||email, which changed
// whenever the profile editor touched the phone — and the saved addresses
// silently disappeared. Storing them here makes them follow the account.
const ADDR_FIELDS = ['name', 'phone', 'house', 'area', 'city', 'state', 'pin', 'type'];

function cleanAddresses(input) {
  if (!Array.isArray(input)) return null;   // null = "not supplied", leave stored value alone
  return input.slice(0, 10).map(a => {
    const out = {};
    if (!a || typeof a !== 'object') return out;
    for (const f of ADDR_FIELDS) out[f] = String(a[f] == null ? '' : a[f]).slice(0, 120);
    return out;
  }).filter(a => a.house || a.city || a.pin);
}

export async function onRequestGet(context) {
  const { request, env } = context;
  await ensureSchema(env.DB);
  const u = await getSessionUser(env, request);
  if (!u) return json({ ok: false, error: 'Not logged in' }, 401);
  const row = await env.DB.prepare('SELECT cart, wishlist, addresses FROM user_data WHERE user_id=?').bind(u.id).first();
  let cart = [], wishlist = [], addresses = [];
  if (row) {
    try { cart = JSON.parse(row.cart || '[]'); } catch (e) {}
    try { wishlist = JSON.parse(row.wishlist || '[]'); } catch (e) {}
    try { addresses = JSON.parse(row.addresses || '[]'); } catch (e) {}
  }
  return json({ ok: true, cart, wishlist, addresses });
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
  // An older client posts only cart+wishlist. Treat a missing `addresses` as
  // "no opinion" and keep what is stored, rather than wiping the address book.
  const cleaned = cleanAddresses(b.addresses);
  let addresses;
  if (cleaned) {
    addresses = JSON.stringify(cleaned);
  } else {
    const row = await env.DB.prepare('SELECT addresses FROM user_data WHERE user_id=?').bind(u.id).first();
    addresses = (row && row.addresses) || '[]';
  }

  await env.DB.prepare(
    `INSERT INTO user_data (user_id, cart, wishlist, addresses, updated_at) VALUES (?,?,?,?,?)
     ON CONFLICT(user_id) DO UPDATE SET cart=excluded.cart, wishlist=excluded.wishlist,
       addresses=excluded.addresses, updated_at=excluded.updated_at`
  ).bind(u.id, cart, wishlist, addresses, Date.now()).run();
  return json({ ok: true });
}
