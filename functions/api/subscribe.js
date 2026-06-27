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

  // Best-effort: add to Brevo contacts AND a Brevo list so the lead is usable in
  // email campaigns (a list-less contact can't be selected as a campaign recipient).
  if (env.BREVO_API_KEY) {
    try {
      const headers = { 'api-key': env.BREVO_API_KEY, 'content-type': 'application/json', 'accept': 'application/json' };
      // Which list to drop subscribers into: BREVO_LIST_ID if configured,
      // otherwise auto-pick the account's first contact list.
      let listIds = [];
      if (env.BREVO_LIST_ID) {
        listIds = [Number(env.BREVO_LIST_ID)];
      } else {
        try {
          const lr = await fetch('https://api.brevo.com/v3/contacts/lists?limit=1&offset=0&sort=asc', { headers });
          const lj = await lr.json();
          if (lj && Array.isArray(lj.lists) && lj.lists[0]) listIds = [lj.lists[0].id];
        } catch (e) {}
      }
      await fetch('https://api.brevo.com/v3/contacts', {
        method: 'POST',
        headers,
        // updateEnabled:true so existing list-less contacts get added to the list too.
        body: JSON.stringify(listIds.length ? { email, updateEnabled: true, listIds } : { email, updateEnabled: true }),
      });
    } catch (e) {}
  }

  return json({ ok: true });
}
