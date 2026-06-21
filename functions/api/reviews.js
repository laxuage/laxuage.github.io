// GET  /api/reviews            -> approved reviews (public storefront)
// POST /api/reviews { product_id, name, rating, text } -> submit (pending moderation)
import { json, ensureSchema } from './_shared.js';

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
  await ensureSchema(env.DB);
  let b;
  try { b = await request.json(); } catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }
  const name = String(b.name || '').trim().slice(0, 60);
  const text = String(b.text || '').trim().slice(0, 800);
  const rating = Math.min(5, Math.max(1, parseInt(b.rating, 10) || 5));
  const pid = parseInt(b.product_id, 10) || null;
  if (!name || !text) return json({ ok: false, error: 'Name and review text are required.' }, 400);
  await env.DB.prepare('INSERT INTO reviews (product_id, name, rating, text, created_at, approved) VALUES (?,?,?,?,?,0)')
    .bind(pid, name, rating, text, Date.now()).run();
  return json({ ok: true, message: 'Thanks! Your review will appear after a quick check.' });
}
