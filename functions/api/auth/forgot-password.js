// POST /api/auth/forgot-password  { email }
// Emails a 6-digit reset code IF an account with a password exists. Always
// returns ok (so the response never reveals whether an email is registered).
import { json, ensureSchema, genOTP, sendOtpEmail, rateLimit, clientIp } from '../_shared.js';

const TTL = 600;                  // reset code valid 10 min
const RESEND_COOLDOWN_MS = 45000; // 45s between sends

export async function onRequestPost(context) {
  const { request, env } = context;
  if (!env.OTP_KV) return json({ ok: false, error: 'Server not configured (KV).' }, 500);
  if (!env.BREVO_API_KEY) return json({ ok: false, error: 'Server not configured (email).' }, 500);
  await ensureSchema(env.DB);

  let b;
  try { b = await request.json(); } catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }
  const email = String(b.email || '').trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ ok: false, error: 'Enter a valid email address.' }, 400);

  // Cap: max 5 codes per email, 10 per IP, per 20-minute window.
  if (!(await rateLimit(env, 'otpc:' + email, 5, 1200)) || !(await rateLimit(env, 'otpip:' + clientIp(request), 10, 1200))) {
    return json({ ok: false, error: 'Too many codes requested. Please try again in about 20 minutes.' }, 429);
  }

  const user = await env.DB.prepare('SELECT id, password_hash FROM users WHERE email=?').bind(email).first();
  if (user && user.password_hash) {
    const key = 'reset:' + email;
    const prevRaw = await env.OTP_KV.get(key);
    if (prevRaw) {
      try { const prev = JSON.parse(prevRaw); if (prev.sentAt && Date.now() - prev.sentAt < RESEND_COOLDOWN_MS) return json({ ok: true }); } catch (e) {}
    }
    const code = genOTP();
    await env.OTP_KV.put(key, JSON.stringify({ code, sentAt: Date.now(), attempts: 0 }), { expirationTtl: TTL });
    await sendOtpEmail(env.BREVO_API_KEY, email, code); // best-effort
  }
  // Always ok — don't leak whether the account exists.
  return json({ ok: true });
}
