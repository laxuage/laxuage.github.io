// POST /api/auth/verify-signup  { email, code }
// Confirms the emailed code, creates (or password-enables) the user, issues a session.
import { json, ensureSchema, sessionCookie, createUserSession, timingSafeEqual, sanitizeText } from '../_shared.js';

const SESSION_TTL = 30 * 24 * 60 * 60; // 30 days
const CODE_TTL = 600;                  // must match signup.js

export async function onRequestPost(context) {
  const { request, env } = context;
  if (!env.OTP_KV) return json({ ok: false, error: 'Server not configured.' }, 500);
  try { await ensureSchema(env.DB); } catch (e) {
    return json({ ok: false, error: 'Server storage unavailable. Please try again.' }, 500);
  }

  let b;
  try { b = await request.json(); } catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }
  const email = String(b.email || '').trim().toLowerCase();
  const code = String(b.code || '').trim();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || !/^\d{6}$/.test(code)) {
    return json({ ok: false, error: 'Invalid email or code' }, 400);
  }

  const key = 'signup:' + email;
  const raw = await env.OTP_KV.get(key);
  if (!raw) return json({ ok: false, error: 'Code expired. Please sign up again.' }, 400);
  let rec;
  try { rec = JSON.parse(raw); } catch (e) { await env.OTP_KV.delete(key); return json({ ok: false, error: 'Code expired.' }, 400); }
  // sentAt is the authority on expiry (KV's 60s minimum TTL makes the stored
  // TTL alone unreliable for enforcing an exact window).
  if (Date.now() - (rec.sentAt || 0) > CODE_TTL * 1000) {
    await env.OTP_KV.delete(key);
    return json({ ok: false, error: 'Code expired. Please sign up again.' }, 400);
  }
  if ((rec.attempts || 0) >= 5) { await env.OTP_KV.delete(key); return json({ ok: false, error: 'Too many attempts. Please sign up again.' }, 429); }
  if (!timingSafeEqual(String(rec.code), code)) {
    rec.attempts = (rec.attempts || 0) + 1;
    await env.OTP_KV.put(key, JSON.stringify(rec), { expirationTtl: CODE_TTL });
    return json({ ok: false, error: 'Incorrect code.' }, 400);
  }
  await env.OTP_KV.delete(key);

  const now = Date.now();
  // Defence in depth: the name is rendered in the storefront nav and in the
  // admin panel, so strip anything HTML-ish before it is ever stored.
  const safeName = sanitizeText(rec.name || '', 60) || email.split('@')[0];
  let user = await env.DB.prepare('SELECT id,email,name,phone FROM users WHERE email=?').bind(email).first();
  if (user) {
    await env.DB.prepare('UPDATE users SET name=?, password_hash=?, last_login=?, pw_changed_at=? WHERE id=?')
      .bind(safeName || user.name, rec.password_hash, now, now, user.id).run();
    user.name = safeName || user.name;
  } else {
    const res = await env.DB.prepare('INSERT INTO users (email,name,phone,password_hash,created_at,last_login,pw_changed_at) VALUES (?,?,?,?,?,?,?)')
      .bind(email, safeName, '', rec.password_hash, now, now, now).run();
    user = { id: res.meta && res.meta.last_row_id, email, name: safeName, phone: '' };
  }

  const token = await createUserSession(env, user.id, SESSION_TTL);
  return json({ ok: true, user: { id: user.id, email: user.email, name: user.name, phone: user.phone } }, 200, {
    'Set-Cookie': sessionCookie(request, token, SESSION_TTL),
  });
}
