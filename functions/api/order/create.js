// POST /api/order/create  -> save an order to D1 (called from checkout)
// Public endpoint. Returns the order id and the authoritative server total.
//
// SECURITY: prices, subtotal, total and discount are ALWAYS recomputed
// server-side from the products catalogue. The client cannot tamper with
// what it pays, and can never mark an order 'paid' (only payment/verify can).
import { json, ensureSchema, rateLimit, clientIp } from '../_shared.js';

// Mirror of the storefront coupons (index.html). Kept in sync intentionally.
const COUPONS = {
  WELCOME10: { type: 'percent', value: 10, min: 0 },
  LUX100:    { type: 'flat',    value: 100, min: 999 },
  FIRST500:  { type: 'flat',    value: 500, min: 2000 },
};

export async function onRequestPost(context) {
  const { request, env } = context;
  // Abuse guard: cap orders per IP (generous for real shoppers, blocks flooding).
  if (!(await rateLimit(env, 'order:' + clientIp(request), 20, 600))) {
    return json({ ok: false, error: 'Too many requests. Please wait a moment and try again.' }, 429);
  }
  await ensureSchema(env.DB);
  let b;
  try { b = await request.json(); } catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }

  const items = Array.isArray(b.items) ? b.items : [];
  if (!items.length) return json({ ok: false, error: 'No items in order' }, 400);

  // Recompute every line from the catalogue; reject unknown/inactive products.
  let subtotal = 0;
  const cleanItems = [];
  for (const it of items) {
    const pid = parseInt(it.id, 10);
    const qty = Math.max(1, Math.min(99, parseInt(it.qty, 10) || 1));
    if (!pid) return json({ ok: false, error: 'Invalid item in order' }, 400);
    const row = await env.DB.prepare('SELECT id,name,price,active FROM products WHERE id=?').bind(pid).first();
    if (!row || row.active === 0) {
      return json({ ok: false, error: 'Some items are no longer available. Please refresh and try again.' }, 409);
    }
    const price = parseInt(row.price, 10) || 0;
    subtotal += price * qty;
    cleanItems.push({ id: pid, name: row.name, price, qty });
  }

  // Server-side coupon revalidation (never trust the client discount).
  let discount = 0;
  const code = String(b.coupon || '').trim().toUpperCase();
  if (code && COUPONS[code]) {
    const c = COUPONS[code];
    if (subtotal >= c.min) discount = c.type === 'percent' ? Math.round(subtotal * c.value / 100) : c.value;
  }
  const shipping = 0;
  const total = Math.max(0, subtotal - discount + shipping);

  const id = b.id ? String(b.id).slice(0, 40) : ('LX' + Date.now().toString(36).toUpperCase());
  const now = Date.now();
  const pm = String(b.payment_method || 'cod').slice(0, 20);
  const ps = (pm === 'cod') ? 'cod' : 'pending'; // never 'paid' from here

  // Note: payment_status / payment_id are intentionally NOT updated on conflict,
  // so re-posting an order can never reset a verified 'paid' order back to pending.
  await env.DB.prepare(
    `INSERT INTO orders
       (id, created_at, customer_name, customer_phone, customer_email, address, items, subtotal, shipping, total, payment_method, payment_id, payment_status, status)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?, 'new')
     ON CONFLICT(id) DO UPDATE SET
       items=excluded.items, subtotal=excluded.subtotal, shipping=excluded.shipping, total=excluded.total,
       customer_name=excluded.customer_name, customer_phone=excluded.customer_phone,
       customer_email=excluded.customer_email, address=excluded.address,
       payment_method=excluded.payment_method`
  ).bind(
    id, now,
    String(b.customer_name || '').slice(0, 80),
    String(b.customer_phone || '').slice(0, 20),
    String(b.customer_email || '').slice(0, 120),
    String(b.address || '').slice(0, 500),
    JSON.stringify(cleanItems).slice(0, 8000),
    subtotal, shipping, total,
    pm, '', ps
  ).run();

  return json({ ok: true, id, subtotal, discount, total });
}
