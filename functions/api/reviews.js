// GET  /api/reviews            -> approved reviews (public storefront)
// POST /api/reviews { product_id, name, rating, text } -> submit (pending moderation)
import { json, ensureSchema, rateLimit, clientIp, sanitizeText } from './_shared.js';

export async function onRequestGet(context) {
  const { env } = context;
  await ensureSchema(env.DB);
  const { results } = await env.DB
    .prepare('SELECT id, product_id, name, rating, text, created_at FROM reviews WHERE approved=1 ORDER BY created_at DESC LIMIT 100')
    .all();
  return json({ ok: true, reviews: results || [] });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  // Abuse guard: cap review submissions per IP.
  if (!(await rateLimit(env, 'review:' + clientIp(request), 5, 600))) {
    return json({ ok: false, error: 'Too many reviews submitted. Please try again later.' }, 429);
  }
  await ensureSchema(env.DB);
  let b;
  try { b = await request.json(); } catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }
  // Sanitise: strip HTML/control chars so a review can never inject script
  // anywhere it is rendered (storefront or admin dashboard).
  const name = sanitizeText(b.name, 60);
  const text = sanitizeText(b.text, 800);
  const rating = Math.min(5, Math.max(1, parseInt(b.rating, 10) || 5));
  const pid = parseInt(b.product_id, 10) || 0;
  if (!name || !text) return json({ ok: false, error: 'Name and review text are required.' }, 400);
  // Only allow reviews for products that actually exist and are active.
  const prod = await env.DB.prepare('SELECT id FROM products WHERE id=? AND active=1').bind(pid).first();
  if (!prod) return json({ ok: false, error: 'Invalid product.' }, 400);
  await env.DB.prepare('INSERT INTO reviews (product_id, name, rating, text, created_at, approved) VALUES (?,?,?,?,?,0)')
    .bind(pid, name, rating, text, Date.now()).run();
  return json({ ok: true, message: 'Thanks! Your review will appear after a quick check.' });
}
