// POST /api/payment/create-order  { amount, receipt?, notes? }
// Creates a Razorpay order server-side. Returns order_id + key_id for Checkout.
// Needs env secrets: RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET.
import { json } from '../_shared.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  if (!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET) {
    return json({ ok: false, error: 'Online payments are not configured yet.' }, 500);
  }
  let b;
  try { b = await request.json(); } catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }
  const amount = Math.round(Number(b.amount) || 0); // rupees
  if (amount < 1) return json({ ok: false, error: 'Invalid amount' }, 400);
  const receipt = String(b.receipt || ('LXG' + Date.now())).slice(0, 40);

  const auth = 'Basic ' + btoa(env.RAZORPAY_KEY_ID + ':' + env.RAZORPAY_KEY_SECRET);
  let res, data;
  try {
    res = await fetch('https://api.razorpay.com/v1/orders', {
      method: 'POST',
      headers: { 'authorization': auth, 'content-type': 'application/json' },
      body: JSON.stringify({ amount: amount * 100, currency: 'INR', receipt, notes: b.notes || {} }),
    });
    data = await res.json();
  } catch (e) {
    return json({ ok: false, error: 'Payment gateway unreachable' }, 502);
  }
  if (!res.ok || !data.id) {
    return json({ ok: false, error: (data && data.error && data.error.description) || 'Could not create payment order' }, 502);
  }
  return json({ ok: true, order_id: data.id, amount: data.amount, currency: data.currency, key_id: env.RAZORPAY_KEY_ID });
}
