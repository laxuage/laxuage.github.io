// GET  /api/admin/reviews                  -> all reviews (any status)
// POST /api/admin/reviews { id, action }   -> action: approve | reject | delete
import { json, ensureSchema } from '../_shared.js';

export async function onRequestGet(context) {
  const { env } = context;
  await ensureSchema(env.DB);
  const { results } = await env.DB
    .prepare('SELECT * FROM reviews ORDER BY created_at DESC LIMIT 400')
    .all();
  return json({ ok: true, reviews: results || [] });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  await ensureSchema(env.DB);
  let b;
  try { b = await request.json(); } catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }
  const id = parseInt(b.id, 10);
  const action = String(b.action || '');
  if (!id) return json({ ok: false, error: 'Invalid' }, 400);
  if (action === 'approve') await env.DB.prepare('UPDATE reviews SET approved=1 WHERE id=?').bind(id).run();
  else if (action === 'reject') await env.DB.prepare('UPDATE reviews SET approved=0 WHERE id=?').bind(id).run();
  else if (action === 'delete') await env.DB.prepare('DELETE FROM reviews WHERE id=?').bind(id).run();
  else return json({ ok: false, error: 'Invalid action' }, 400);
  return json({ ok: true });
}
