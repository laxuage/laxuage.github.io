// POST /api/auth/signup  { email, password, name }
// Validates, hashes the password, stores a pending signup, emails a verify code.
// The account is only created after /api/auth/verify-signup confirms the code.
import { json, ensureSchema, genOTP, sendOtpEmail, hashPassword } from '../_shared.js';

const TTL = 600;                  // pending signup valid 10 min
const RESEND_COOLDOWN_MS = 45000; // 45s between sends

export async function onRequestPost(context) {
  const { request, env } = context;
  if (!env.OTP_KV) return json({ ok: false, error: 'Server not configured (KV).' }, 500);
  if (!env.BREVO_API_KEY) return json({ ok: false, error: 'Server not configured (email).' }, 500);
  await ensureSchema(env.DB);

  let b;
  try { b = await request.json(); } catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }
  const email = String(b.email || '').trim().toLowerCase();
  const password = String(b.password || '');
  const name = String(b.name || '').trim().slice(0, 60);
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ ok: false, error: 'Enter a valid email address.' }, 400);
  if (password.length < 6) return json({ ok: false, error: 'Password must be at least 6 characters.' }, 400);

  // Already registered (with a password)? -> tell them to sign in.
  const existing = await env.DB.prepare('SELECT id, password_hash FROM users WHERE email=?').bind(email).first();
  if (existing && existing.password_hash) {
    return json({ ok: false, error: 'An account with this email already exists. Please sign in.' }, 409);
  }

  const key = 'signup:' + email;
  const prevRaw = await env.OTP_KV.get(key);
  if (prevRaw) {
    try { const prev = JSON.parse(prevRaw); if (prev.sentAt && Date.now() - prev.sentAt < RESEND_COOLDOWN_MS) return json({ ok: false, error: 'Please wait a few seconds before requesting another code.' }, 429); } catch (e) {}
  }

  const code = genOTP();
  const password_hash = await hashPassword(password);
  await env.OTP_KV.put(key, JSON.stringify({ code, name, password_hash, sentAt: Date.now(), attempts: 0 }), { expirationTtl: TTL });

  const sent = await sendOtpEmail(env.BREVO_API_KEY, email, code);
  if (!sent) return json({ ok: false, error: 'Could not send the email right now. Please try again.' }, 502);
  return json({ ok: true });
}
