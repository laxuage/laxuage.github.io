// POST /api/payment/verify
//   { razorpay_order_id, razorpay_payment_id, razorpay_signature, order_id? }
// Verifies the Razorpay signature server-side, then marks our order paid.
import { json, ensureSchema } from '../_shared.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  if (!env.RAZORPAY_KEY_SECRET) return json({ ok: false, error: 'Payments not configured.' }, 500);
  await ensureSchema(env.DB);

  let b;
  try { b = await request.json(); } catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }
  const roid = String(b.razorpay_order_id || '');
  const rpid = String(b.razorpay_payment_id || '');
  const rsig = String(b.razorpay_signature || '');
  if (!roid || !rpid || !rsig) return json({ ok: false, error: 'Missing payment fields' }, 400);

  const expected = await hmacHex(env.RAZORPAY_KEY_SECRET, roid + '|' + rpid);
  // constant-time-ish compare
  if (expected.length !== rsig.length) return json({ ok: false, error: 'Payment verification failed' }, 400);
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ rsig.charCodeAt(i);
  if (diff !== 0) return json({ ok: false, error: 'Payment verification failed' }, 400);

  // Mark our order paid — but only if the Razorpay order that was just paid is
  // the one we bound to this order at create time. This stops a buyer from
  // paying a cheap Razorpay order and replaying its signature against an
  // expensive internal order.
  if (b.order_id) {
    try {
      const ord = await env.DB.prepare('SELECT id, rp_order_id FROM orders WHERE id=?')
        .bind(String(b.order_id)).first();
      if (ord) {
        if (ord.rp_order_id && ord.rp_order_id !== roid) {
          return json({ ok: false, error: 'Payment does not match this order' }, 400);
        }
        await env.DB.prepare("UPDATE orders SET payment_status='paid', payment_id=? WHERE id=?")
          .bind(rpid, String(b.order_id)).run();
      }
    } catch (e) {}
  }
  return json({ ok: true });
}

async function hmacHex(secret, data) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return Array.from(new Uint8Array(sig)).map(x => x.toString(16).padStart(2, '0')).join('');
}
