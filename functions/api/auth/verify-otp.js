// POST /api/auth/verify-otp   body: { email, code }
// Checks the code against OTP_KV. Max 5 attempts. Deletes on success.

const MAX_ATTEMPTS = 5;
const TTL_SECONDS = 600;

export async function onRequestPost(context) {
  const { request, env } = context;

  if (!env.OTP_KV) return json({ ok: false, error: 'Server not configured (KV).' }, 500);

  let email, code;
  try {
    const data = await request.json();
    email = String(data.email || '').trim().toLowerCase();
    code = String(data.code || '').trim();
  } catch (e) {
    return json({ ok: false, error: 'Bad request.' }, 400);
  }

  if (!isValidEmail(email) || !/^\d{6}$/.test(code)) {
    return json({ ok: false, error: 'Invalid input.' }, 400);
  }

  const key = 'otp:' + email;
  const raw = await env.OTP_KV.get(key);
  if (!raw) return json({ ok: false, error: 'Code expired. Please request a new one.' }, 400);

  let rec;
  try { rec = JSON.parse(raw); } catch (e) {
    await env.OTP_KV.delete(key);
    return json({ ok: false, error: 'Code expired. Please request a new one.' }, 400);
  }

  if ((rec.attempts || 0) >= MAX_ATTEMPTS) {
    await env.OTP_KV.delete(key);
    return json({ ok: false, error: 'Too many attempts. Please request a new code.' }, 429);
  }

  if (rec.code !== code) {
    rec.attempts = (rec.attempts || 0) + 1;
    await env.OTP_KV.put(key, JSON.stringify(rec), { expirationTtl: TTL_SECONDS });
    return json({ ok: false, error: 'Incorrect code. Please try again.' }, 400);
  }

  // Success — consume the code
  await env.OTP_KV.delete(key);
  return json({ ok: true });
}

function isValidEmail(e) {
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e);
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}
