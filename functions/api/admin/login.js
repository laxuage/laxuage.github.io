// POST /api/admin/login  { password }  -> sets HttpOnly admin session cookie
import { json, genToken, getCookie, ensureSchema } from '../_shared.js';

const SESSION_TTL = 7 * 24 * 60 * 60; // 7 days

export async function onRequestPost(context) {
  const { request, env } = context;
  if (!env.ADMIN_PASSWORD) return json({ ok: false, error: 'Admin not configured (set ADMIN_PASSWORD).' }, 500);

  // Basic brute-force throttle per IP (10 / 10 min).
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rlKey = 'adminrl:' + ip;
  try {
    const n = parseInt((await env.OTP_KV.get(rlKey)) || '0', 10);
    if (n >= 10) return json({ ok: false, error: 'Too many attempts. Try again later.' }, 429);
    await env.OTP_KV.put(rlKey, String(n + 1), { expirationTtl: 600 });
  } catch (e) {}

  let pw = '';
  try { pw = String((await request.json()).password || ''); }
  catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }

  // Length check first avoids leaking via early-exit on mismatched lengths.
  const expected = env.ADMIN_PASSWORD;
  let ok = pw.length === expected.length;
  let diff = 0;
  for (let i = 0; i < Math.max(pw.length, expected.length); i++) {
    diff |= (pw.charCodeAt(i) || 0) ^ (expected.charCodeAt(i) || 0);
  }
  ok = ok && diff === 0;
  if (!ok) return json({ ok: false, error: 'Wrong password' }, 401);

  const token = genToken();
  await env.OTP_KV.put('adminsess:' + token, '1', { expirationTtl: SESSION_TTL });
  try { await ensureSchema(env.DB); } catch (e) {}

  return json({ ok: true }, 200, {
    'Set-Cookie': 'lax_admin=' + token + '; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=' + SESSION_TTL,
  });
}
