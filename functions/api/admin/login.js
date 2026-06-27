// POST /api/admin/login  { password }  -> sets HttpOnly admin session cookie
import { json, genToken, getCookie, ensureSchema } from '../_shared.js';

const SESSION_TTL = 24 * 60 * 60; // 1 day (shorter window if a token ever leaks)

export async function onRequestPost(context) {
  const { request, env } = context;
  if (!env.ADMIN_PASSWORD) return json({ ok: false, error: 'Admin not configured (set ADMIN_PASSWORD).' }, 500);

  // Brute-force protection with exponential backoff (per IP). After 5 failed
  // attempts the IP is locked, and each failure lengthens the lockout window.
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const failKey = 'adminfail:' + ip;
  let fails = 0;
  try { fails = parseInt((await env.OTP_KV.get(failKey)) || '0', 10); } catch (e) {}
  if (fails >= 5) {
    return json({ ok: false, error: 'Too many failed attempts. Please wait a few minutes and try again.' }, 429);
  }

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
  if (!ok) {
    const next = fails + 1;
    const ttl = Math.min(3600, 180 * next); // 3,6,9,12,15 min … capped at 1h
    try { await env.OTP_KV.put(failKey, String(next), { expirationTtl: ttl }); } catch (e) {}
    return json({ ok: false, error: 'Wrong password' }, 401);
  }
  try { await env.OTP_KV.delete(failKey); } catch (e) {} // reset on success

  const token = genToken();
  await env.OTP_KV.put('adminsess:' + token, '1', { expirationTtl: SESSION_TTL });
  try { await ensureSchema(env.DB); } catch (e) {}

  return json({ ok: true }, 200, {
    'Set-Cookie': 'lax_admin=' + token + '; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=' + SESSION_TTL,
  });
}
