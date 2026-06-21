// POST /api/order/create  -> save an order to D1 (called from checkout)
// Public endpoint. Returns the order id.
import { json, ensureSchema } from '../_shared.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  await ensureSchema(env.DB);
  let b;
  try { b = await request.json(); } catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }

  const items = Array.isArray(b.items) ? b.items : [];
  if (!items.length) return json({ ok: false, error: 'No items in order' }, 400);

  const id = b.id ? String(b.id).slice(0, 40) : ('LX' + Date.now().toString(36).toUpperCase());
  const now = Date.now();
  const subtotal = parseInt(b.subtotal, 10) || 0;
  const shipping = parseInt(b.shipping, 10) || 0;
  const total = parseInt(b.total, 10) || (subtotal + shipping);
  const pm = String(b.payment_method || 'cod').slice(0, 20);
  const ps = String(b.payment_status || (pm === 'cod' ? 'cod' : 'pending')).slice(0, 20);

  await env.DB.prepare(
    `INSERT INTO orders
       (id, created_at, customer_name, customer_phone, customer_email, address, items, subtotal, shipping, total, payment_method, payment_id, payment_status, status)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?, 'new')
     ON CONFLICT(id) DO UPDATE SET payment_id=excluded.payment_id, payment_status=excluded.payment_status`
  ).bind(
    id, now,
    String(b.customer_name || '').slice(0, 80),
    String(b.customer_phone || '').slice(0, 20),
    String(b.customer_email || '').slice(0, 120),
    String(b.address || '').slice(0, 500),
    JSON.stringify(items).slice(0, 8000),
    subtotal, shipping, total,
    pm, String(b.payment_id || '').slice(0, 60), ps
  ).run();

  return json({ ok: true, id });
}
