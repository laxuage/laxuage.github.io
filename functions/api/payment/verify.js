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

  // A valid signature only proves that SOME payment succeeded. It says nothing
  // about WHICH of our orders that payment was for — so everything below binds
  // the payment to this specific order before marking it paid.
  const oid = String(b.order_id || '');
  if (!oid) return json({ ok: false, error: 'Missing order reference' }, 400);

  // Note the deliberate absence of a blanket try/catch here: a D1 error must
  // NOT fall through to `ok: true`. An unconfirmed payment the owner reconciles
  // by hand is recoverable; goods shipped against a payment that never landed
  // are not.
  let ord;
  try {
    ord = await env.DB.prepare('SELECT id, rp_order_id, total, customer_email, payment_status, payment_id FROM orders WHERE id=?')
      .bind(oid).first();
  } catch (e) {
    return json({ ok: false, error: 'Could not confirm payment yet. We will verify shortly.' }, 503);
  }
  if (!ord) return json({ ok: false, error: 'Order not found' }, 404);

  // Already settled by this exact payment — replaying the same callback (double
  // submit, retry, refresh) is not an attack, so stay idempotent.
  if (ord.payment_status === 'paid' && ord.payment_id === rpid) return json({ ok: true });

  // The payment must be for the Razorpay order we bound to THIS order at create
  // time. A missing binding is now a hard reject: create-order refuses to start
  // a payment it cannot bind, so from here on every genuine payment has one.
  // Without this, an unbound order accepts any valid signature — pay for a
  // cheap order, replay that signature against an expensive one.
  if (!ord.rp_order_id || ord.rp_order_id !== roid) {
    await audit(env, request, ord.rp_order_id ? 'verify_order_mismatch' : 'verify_unbound_order', {
      order_id: oid, total: ord.total, bound: ord.rp_order_id || null,
      razorpay_order_id: roid, razorpay_payment_id: rpid,
    });
    return json({ ok: false, error: 'Payment does not match this order' }, 400);
  }

  // One payment settles one order. Without this a single genuine payment could
  // be replayed across many orders that each happen to be bound to it.
  try {
    const clash = await env.DB.prepare('SELECT id FROM orders WHERE payment_id=? AND id<>?').bind(rpid, oid).first();
    if (clash) {
      await audit(env, request, 'verify_payment_reuse', { order_id: oid, already_used_by: clash.id, razorpay_payment_id: rpid });
      return json({ ok: false, error: 'This payment has already been used' }, 400);
    }
  } catch (e) {
    return json({ ok: false, error: 'Could not confirm payment yet. We will verify shortly.' }, 503);
  }

  try {
    await env.DB.prepare("UPDATE orders SET payment_status='paid', payment_id=? WHERE id=?").bind(rpid, oid).run();
  } catch (e) {
    return json({ ok: false, error: 'Could not confirm payment yet. We will verify shortly.' }, 503);
  }

  // Best-effort server-side Purchase to Meta (Conversions API) for accurate
  // ad attribution. Dormant unless META_CAPI_TOKEN is configured; never
  // affects the response. event_id = order id so it dedupes with the
  // browser pixel's Purchase (which sends the same eventID).
  if (env.META_CAPI_TOKEN) { await sendMetaPurchase(env, request, ord).catch(() => {}); }
  return json({ ok: true });
}

// Records a rejected verification for later review. Never throws — a failure to
// log must not change the caller's decision.
async function audit(env, request, kind, detail) {
  console.warn('payment/verify: ' + kind, JSON.stringify(detail));
  try {
    await env.DB.prepare('INSERT INTO audit_log (created_at,kind,detail) VALUES (?,?,?)')
      .bind(Date.now(), kind, JSON.stringify(Object.assign({
        ip: request.headers.get('CF-Connecting-IP') || '',
      }, detail)).slice(0, 900)).run();
  } catch (e) {}
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
