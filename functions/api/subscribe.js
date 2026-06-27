// POST /api/subscribe  { email }
// Newsletter signup: stores the lead in D1 (so the shop owner actually keeps it)
// and best-effort adds it to the Brevo contact list for future campaigns.
import { json, ensureSchema, rateLimit, clientIp } from './_shared.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  // Abuse guard: cap signups per IP.
  if (!(await rateLimit(env, 'sub:' + clientIp(request), 8, 600))) {
    return json({ ok: false, error: 'Too many requests. Please try again later.' }, 429);
  }
  await ensureSchema(env.DB);

  let b;
  try { b = await request.json(); } catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }
  const email = String(b.email || '').trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return json({ ok: false, error: 'Enter a valid email address.' }, 400);
  }

  // Persist the lead (idempotent — re-subscribing is a no-op).
  try {
    await env.DB.prepare(
      'INSERT INTO subscribers (email, created_at, source) VALUES (?,?,?) ON CONFLICT(email) DO NOTHING'
    ).bind(email, Date.now(), 'newsletter').run();
  } catch (e) {}

  // Best-effort: add to Brevo contacts so it's usable in email campaigns.
  if (env.BREVO_API_KEY) {
    try {
      await fetch('https://api.brevo.com/v3/contacts', {
        method: 'POST',
        headers: { 'api-key': env.BREVO_API_KEY, 'content-type': 'application/json', 'accept': 'application/json' },
        body: JSON.stringify({ email, updateEnabled: true }),
      });
    } catch (e) {}
  }

  return json({ ok: true });
}
