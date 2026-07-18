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
      const ord = await env.DB.prepare('SELECT id, rp_order_id, total, customer_email FROM orders WHERE id=?')
        .bind(String(b.order_id)).first();
      if (ord) {
        if (ord.rp_order_id && ord.rp_order_id !== roid) {
          return json({ ok: false, error: 'Payment does not match this order' }, 400);
        }
        if (!ord.rp_order_id) {
          // No Razorpay order was ever bound to this order, so the signature
          // above proves only that SOME payment succeeded — not that it was
          // for this order. That is exactly the shape of a replayed-payment
          // attack: pay for a cheap order, then present that signature against
          // an expensive one that never went through create-order.
          //
          // PHASE 1 — observe, don't block. Legacy orders predating the
          // rp_order_id column would be rejected by a hard fail, so for now we
          // record and still accept. Once these stop appearing in audit_log,
          // this becomes a hard reject (and see create-order.js, which now
          // refuses to start a payment it cannot bind).
          console.warn('payment/verify: unbound order accepted', String(b.order_id), roid, rpid);
          try {
            await env.DB.prepare('INSERT INTO audit_log (created_at,kind,detail) VALUES (?,?,?)')
              .bind(Date.now(), 'verify_unbound_order', JSON.stringify({
                order_id: String(b.order_id), total: ord.total,
                razorpay_order_id: roid, razorpay_payment_id: rpid,
                ip: request.headers.get('CF-Connecting-IP') || '',
              }).slice(0, 900)).run();
          } catch (e) {}
        }
        await env.DB.prepare("UPDATE orders SET payment_status='paid', payment_id=? WHERE id=?")
          .bind(rpid, String(b.order_id)).run();
        // Best-effort server-side Purchase to Meta (Conversions API) for accurate
        // ad attribution. Dormant unless META_CAPI_TOKEN is configured; never
        // affects the response. event_id = order id so it dedupes with the
        // browser pixel's Purchase (which sends the same eventID).
        if (env.META_CAPI_TOKEN) { await sendMetaPurchase(env, request, ord).catch(() => {}); }
      }
    } catch (e) {}
  }
  return json({ ok: true });
}

async function sha256Hex(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map(x => x.toString(16).padStart(2, '0')).join('');
}

async function sendMetaPurchase(env, request, ord) {
  const pixelId = env.META_PIXEL_ID || '1460163436124169';
  const user_data = {};
  if (ord.customer_email) user_data.em = [await sha256Hex(String(ord.customer_email).trim().toLowerCase())];
  const ip = request.headers.get('CF-Connecting-IP'); if (ip) user_data.client_ip_address = ip;
  const ua = request.headers.get('User-Agent'); if (ua) user_data.client_user_agent = ua;
  await fetch('https://graph.facebook.com/v19.0/' + pixelId + '/events?access_token=' + encodeURIComponent(env.META_CAPI_TOKEN), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ data: [{
      event_name: 'Purchase',
      event_time: Math.floor(Date.now() / 1000),
      action_source: 'website',
      event_id: String(ord.id),
      user_data,
      custom_data: { currency: 'INR', value: Number(ord.total) || 0, order_id: String(ord.id) },
    }] }),
  });
}

async function hmacHex(secret, data) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return Array.from(new Uint8Array(sig)).map(x => x.toString(16).padStart(2, '0')).join('');
}
