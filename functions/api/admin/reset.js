// POST /api/admin/reset  { code, new_password }
// Verifies the emailed code and sets a new admin password.
//
// ADMIN_PASSWORD is a Cloudflare env var and a Worker cannot rewrite its own
// env, so the new password is stored as a PBKDF2 hash in D1 (settings.admin_password).
// verifyAdminPassword() prefers that override over the env secret from then on.
import { json, ensureSchema, setAdminPassword, rateLimit, clientIp, timingSafeEqual } from '../_shared.js';

const KEY = 'adminreset';
const MIN_LEN = 8;
const CODE_TTL = 600;      // must match forgot.js
// There is only ONE admin code, so its attempt counter is inherently shared —
// which means any anonymous caller could burn it and destroy a code the owner
// is holding. So the PER-IP budget is the real guard (a stranger can only spend
// their own), and the global counter is set high enough that it cannot be
// cheaply exhausted, while still capping brute force: 60 guesses against a
// 900,000-space code is a ~0.007% chance.
const IP_GUESSES = 5;
const MAX_ATTEMPTS = 60;

export async function onRequestPost(context) {
  const { request, env } = context;
  if (!env.OTP_KV) return json({ ok: false, error: 'Server not configured (KV).' }, 500);
  try { await ensureSchema(env.DB); } catch (e) {
    return json({ ok: false, error: 'Server storage unavailable. Please try again.' }, 500);
  }

  let b;
  try { b = await request.json(); } catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }
  const code = String(b.code || '').trim();
  const pw = String(b.new_password || '');

  if (!/^\d{6}$/.test(code)) return json({ ok: false, error: 'Enter the 6-digit code from the email.' }, 400);
  if (pw.length < MIN_LEN) return json({ ok: false, error: 'New password must be at least ' + MIN_LEN + ' characters.' }, 400);

  // Per-IP: an attacker can only ever exhaust their own guess budget, so they
  // cannot lock the owner out of using a code they are already holding.
  if (!(await rateLimit(env, 'admresetv:' + clientIp(request), IP_GUESSES, 1800))) {
    return json({ ok: false, error: 'Too many attempts from this network. Please try again later.' }, 429);
  }

  const raw = await env.OTP_KV.get(KEY);
  if (!raw) return json({ ok: false, error: 'Code expired. Please request a new reset code.' }, 400);

  let rec;
  try { rec = JSON.parse(raw); } catch (e) {
    await env.OTP_KV.delete(KEY);
    return json({ ok: false, error: 'Code expired. Please request a new reset code.' }, 400);
  }

  // sentAt is the AUTHORITY on expiry; the KV TTL is only a garbage collector.
  // KV has a 60s minimum TTL, so re-putting on each wrong guess could otherwise
  // nudge the deadline outward. This keeps the 10-minute window exact.
  if (Date.now() - (rec.sentAt || 0) > CODE_TTL * 1000) {
    await env.OTP_KV.delete(KEY);
    return json({ ok: false, error: 'Code expired. Please request a new reset code.' }, 400);
  }

  if ((rec.attempts || 0) >= MAX_ATTEMPTS) {
    await env.OTP_KV.delete(KEY);
    return json({ ok: false, error: 'Too many incorrect attempts. Please request a new code.' }, 429);
  }

  if (!timingSafeEqual(String(rec.code), code)) {
    rec.attempts = (rec.attempts || 0) + 1;
    await env.OTP_KV.put(KEY, JSON.stringify(rec), { expirationTtl: CODE_TTL });
    const leftTries = MAX_ATTEMPTS - rec.attempts;
    return json({ ok: false, error: 'Incorrect code.' + (leftTries > 0 ? ' ' + leftTries + ' attempt' + (leftTries === 1 ? '' : 's') + ' left.' : '') }, 400);
  }

  await env.OTP_KV.delete(KEY);

  // Stores the hash AND revokes every existing admin session, so a reset
  // prompted by a suspected compromise actually kicks the intruder out.
  await setAdminPassword(env, pw);

  // Clear this IP's login lockout so the owner can sign in immediately.
  try { await env.OTP_KV.delete('adminfail:' + clientIp(request)); } catch (e) {}

  return json({ ok: true }, 200, {
    // The current admin cookie (if any) is now pre-epoch and therefore dead;
    // clear it so the panel doesn't show a half-authenticated state.
    'Set-Cookie': 'lax_admin=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0',
  });
}
