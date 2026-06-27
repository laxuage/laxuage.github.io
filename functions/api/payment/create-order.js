// POST /api/payment/create-order  { order_id }   (legacy: { receipt } also accepted)
// Creates a Razorpay order server-side. The amount is taken from the SAVED order
// in D1 (authoritative) — never from the client — and the Razorpay order id is
// bound to our order so /api/payment/verify can confirm the amount paid.
// Needs env secrets: RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET.
import { json, ensureSchema, rateLimit, clientIp } from '../_shared.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  if (!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET) {
    return json({ ok: false, error: 'Online payments are not configured yet.' }, 500);
  }
  // Abuse guard: cap payment-order creation per IP (protects the Razorpay key).
  if (!(await rateLimit(env, 'pay:' + clientIp(request), 20, 600))) {
    return json({ ok: false, error: 'Too many requests. Please wait a moment and try again.' }, 429);
  }
  await ensureSchema(env.DB);
  let b;
  try { b = await request.json(); } catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }

  // The order must already have been saved by /api/order/create (which computed
  // the authoritative total). Accept order_id, or the legacy `receipt` field
  // which older clients send equal to the order id.
  const oid = String(b.order_id || b.receipt || '').slice(0, 40);
  if (!oid) return json({ ok: false, error: 'Missing order reference' }, 400);
  const order = await env.DB.prepare('SELECT id,total FROM orders WHERE id=?').bind(oid).first();
  if (!order) return json({ ok: false, error: 'Order not found. Please retry checkout.' }, 404);
  const amount = Math.round(Number(order.total) || 0); // rupees, authoritative
  if (amount < 1) return json({ ok: false, error: 'Invalid order amount' }, 400);

  const auth = 'Basic ' + btoa(env.RAZORPAY_KEY_ID + ':' + env.RAZORPAY_KEY_SECRET);
  let res, data;
  try {
    res = await fetch('https://api.razorpay.com/v1/orders', {
      method: 'POST',
      headers: { 'authorization': auth, 'content-type': 'application/json' },
      body: JSON.stringify({ amount: amount * 100, currency: 'INR', receipt: oid, notes: { order_id: oid } }),
    });
    data = await res.json();
  } catch (e) {
    return json({ ok: false, error: 'Payment gateway unreachable' }, 502);
  }
  if (!res.ok || !data.id) {
    return json({ ok: false, error: (data && data.error && data.error.description) || 'Could not create payment order' }, 502);
  }

  // Bind the Razorpay order to our order so verify.js can check it.
  try { await env.DB.prepare('UPDATE orders SET rp_order_id=? WHERE id=?').bind(String(data.id), oid).run(); } catch (e) {}

  return json({ ok: true, order_id: data.id, amount: data.amount, currency: data.currency, key_id: env.RAZORPAY_KEY_ID });
}
