// POST /api/auth/login  { email, password }
// Verifies the password and issues a 30-day session cookie.
import { json, genToken, ensureSchema, verifyPassword, sessionCookie } from '../_shared.js';

const SESSION_TTL = 30 * 24 * 60 * 60; // 30 days

export async function onRequestPost(context) {
  const { request, env } = context;
  await ensureSchema(env.DB);

  let b;
  try { b = await request.json(); } catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }
  const email = String(b.email || '').trim().toLowerCase();
  const password = String(b.password || '');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || !password) {
    return json({ ok: false, error: 'Enter your email and password.' }, 400);
  }

  const user = await env.DB.prepare('SELECT id,email,name,phone,password_hash FROM users WHERE email=?').bind(email).first();
  if (!user) return json({ ok: false, error: 'No account found with this email. Please create an account.' }, 404);
  if (!user.password_hash) return json({ ok: false, error: 'This email has no password yet. Please use "Create Account" to set one.' }, 403);

  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) return json({ ok: false, error: 'Incorrect password.' }, 401);

  await env.DB.prepare('UPDATE users SET last_login=? WHERE id=?').bind(Date.now(), user.id).run();
  const token = genToken();
  await env.OTP_KV.put('usersess:' + token, String(user.id), { expirationTtl: SESSION_TTL });

  return json({ ok: true, user: { id: user.id, email: user.email, name: user.name, phone: user.phone } }, 200, {
    'Set-Cookie': sessionCookie(request, token, SESSION_TTL),
  });
}
