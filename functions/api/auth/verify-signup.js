// POST /api/auth/verify-signup  { email, code }
// Confirms the emailed code, creates (or password-enables) the user, issues a session.
import { json, genToken, ensureSchema } from '../_shared.js';

const SESSION_TTL = 30 * 24 * 60 * 60; // 30 days

export async function onRequestPost(context) {
  const { request, env } = context;
  await ensureSchema(env.DB);

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
  if ((rec.attempts || 0) >= 5) { await env.OTP_KV.delete(key); return json({ ok: false, error: 'Too many attempts. Please sign up again.' }, 429); }
  if (rec.code !== code) {
    rec.attempts = (rec.attempts || 0) + 1;
    await env.OTP_KV.put(key, JSON.stringify(rec), { expirationTtl: 600 });
    return json({ ok: false, error: 'Incorrect code.' }, 400);
  }
  await env.OTP_KV.delete(key);

  const now = Date.now();
  let user = await env.DB.prepare('SELECT id,email,name,phone FROM users WHERE email=?').bind(email).first();
  if (user) {
    await env.DB.prepare('UPDATE users SET name=?, password_hash=?, last_login=? WHERE id=?')
      .bind(rec.name || user.name, rec.password_hash, now, user.id).run();
    if (rec.name) user.name = rec.name;
  } else {
    const res = await env.DB.prepare('INSERT INTO users (email,name,phone,password_hash,created_at,last_login) VALUES (?,?,?,?,?,?)')
      .bind(email, rec.name || email.split('@')[0], '', rec.password_hash, now, now).run();
    user = { id: res.meta && res.meta.last_row_id, email, name: rec.name || email.split('@')[0], phone: '' };
  }

  const token = genToken();
  await env.OTP_KV.put('usersess:' + token, String(user.id), { expirationTtl: SESSION_TTL });
  return json({ ok: true, user: { id: user.id, email: user.email, name: user.name, phone: user.phone } }, 200, {
    'Set-Cookie': 'lax_session=' + token + '; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=' + SESSION_TTL,
  });
}
