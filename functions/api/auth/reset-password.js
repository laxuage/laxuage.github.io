// POST /api/auth/reset-password  { email, code, password }
// Verifies the emailed reset code, sets the new password, signs the user in.
import { json, ensureSchema, hashPassword, sessionCookie, createUserSession, rateLimit, clientIp, timingSafeEqual } from '../_shared.js';

const SESSION_TTL = 30 * 24 * 60 * 60; // 30 days
const CODE_TTL = 600;                  // must match forgot-password.js
const MAX_ATTEMPTS = 5;

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
  const password = String(b.password || '');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || !/^\d{6}$/.test(code)) return json({ ok: false, error: 'Invalid email or code' }, 400);
  if (password.length < 6) return json({ ok: false, error: 'Password must be at least 6 characters.' }, 400);

  // Per-IP AND per-email. With only the per-IP cap, an attacker could rotate
  // IPs and keep guessing one victim's code; the per-email cap bounds the
  // guesses against any single account no matter where they come from.
  if (!(await rateLimit(env, 'resetip:' + clientIp(request), 20, 1200))) {
    return json({ ok: false, error: 'Too many attempts. Please try again later.' }, 429);
  }
  if (!(await rateLimit(env, 'resetem:' + email, 10, 1200))) {
    return json({ ok: false, error: 'Too many attempts for this account. Please try again later.' }, 429);
  }

  const key = 'reset:' + email;
  const raw = await env.OTP_KV.get(key);
  if (!raw) return json({ ok: false, error: 'Code expired. Please request a new reset code.' }, 400);
  let rec;
  try { rec = JSON.parse(raw); } catch (e) { await env.OTP_KV.delete(key); return json({ ok: false, error: 'Code expired.' }, 400); }

  // sentAt is the AUTHORITY on expiry; the KV TTL is only a garbage collector.
  // KV cannot store a TTL under 60s, so re-putting the record on each wrong
  // guess could otherwise nudge the deadline outward. Checking the timestamp
  // makes the 10-minute window exact and un-gameable.
  if (Date.now() - (rec.sentAt || 0) > CODE_TTL * 1000) {
    await env.OTP_KV.delete(key);
    return json({ ok: false, error: 'Code expired. Please request a new reset code.' }, 400);
  }
  if ((rec.attempts || 0) >= MAX_ATTEMPTS) { await env.OTP_KV.delete(key); return json({ ok: false, error: 'Too many attempts. Please request a new code.' }, 429); }

  if (!timingSafeEqual(String(rec.code), code)) {
    rec.attempts = (rec.attempts || 0) + 1;
    await env.OTP_KV.put(key, JSON.stringify(rec), { expirationTtl: CODE_TTL });
    return json({ ok: false, error: 'Incorrect code.' }, 400);
  }
  await env.OTP_KV.delete(key);

  const user = await env.DB.prepare('SELECT id,email,name,phone FROM users WHERE email=?').bind(email).first();
  if (!user) return json({ ok: false, error: 'No account found for this email.' }, 404);

  const password_hash = await hashPassword(password);
  const now = Date.now();
  // pw_changed_at revokes every session minted before this moment (getSessionUser).
  // Without it, an attacker holding a stolen 30-day cookie kept full access to
  // the account the victim just "secured" by resetting.
  await env.DB.prepare('UPDATE users SET password_hash=?, last_login=?, pw_changed_at=? WHERE id=?')
    .bind(password_hash, now, now, user.id).run();

  // Clear any login lockout so the user can sign in right away.
  try { await env.OTP_KV.delete('loginfail:' + email); } catch (e) {}

  // Minted after pw_changed_at, so this new session survives the revocation.
  const token = await createUserSession(env, user.id, SESSION_TTL);
  return json({ ok: true, user: { id: user.id, email: user.email, name: user.name, phone: user.phone } }, 200, {
    'Set-Cookie': sessionCookie(request, token, SESSION_TTL),
  });
}
