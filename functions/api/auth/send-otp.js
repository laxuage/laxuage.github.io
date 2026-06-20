// POST /api/auth/send-otp   body: { email }
// Generates a 6-digit OTP, stores it in OTP_KV (10 min TTL), emails it via Brevo.
// Secrets/bindings used: env.BREVO_API_KEY (secret), env.OTP_KV (KV namespace).

const SENDER = { name: 'Laxuage', email: 'support@laxuage.com' };
const TTL_SECONDS = 600;        // OTP valid for 10 minutes
const RESEND_COOLDOWN_MS = 45000; // 45s between sends per email

export async function onRequestPost(context) {
  const { request, env } = context;

  if (!env.OTP_KV) return json({ ok: false, error: 'Server not configured (KV).' }, 500);
  if (!env.BREVO_API_KEY) return json({ ok: false, error: 'Server not configured (email).' }, 500);

  let email;
  try {
    const data = await request.json();
    email = String(data.email || '').trim().toLowerCase();
  } catch (e) {
    return json({ ok: false, error: 'Bad request.' }, 400);
  }
  if (!isValidEmail(email)) return json({ ok: false, error: 'Enter a valid email address.' }, 400);

  const key = 'otp:' + email;

  // Resend cooldown
  const existingRaw = await env.OTP_KV.get(key);
  if (existingRaw) {
    try {
      const existing = JSON.parse(existingRaw);
      if (existing.sentAt && Date.now() - existing.sentAt < RESEND_COOLDOWN_MS) {
        return json({ ok: false, error: 'Please wait a few seconds before requesting another code.' }, 429);
      }
    } catch (e) {}
  }

  const code = genOTP();
  const record = { code, sentAt: Date.now(), attempts: 0 };
  await env.OTP_KV.put(key, JSON.stringify(record), { expirationTtl: TTL_SECONDS });

  const sent = await sendBrevoEmail(env.BREVO_API_KEY, email, code);
  if (!sent) return json({ ok: false, error: 'Could not send the email right now. Please try again.' }, 502);

  return json({ ok: true });
}

function genOTP() {
  const a = new Uint32Array(1);
  crypto.getRandomValues(a);
  return String(100000 + (a[0] % 900000));
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

async function sendBrevoEmail(apiKey, to, code) {
  const html = `
  <div style="font-family:Arial,Helvetica,sans-serif;max-width:480px;margin:0 auto;background:#fbf7f1;padding:32px 24px;border-radius:8px">
    <div style="text-align:center;margin-bottom:24px">
      <span style="font-family:Georgia,serif;font-size:26px;font-style:italic;color:#7E2D49;letter-spacing:1px">Laxuage</span>
      <div style="font-size:11px;letter-spacing:3px;color:#b08d57;text-transform:uppercase;margin-top:2px">Made of Her</div>
    </div>
    <p style="color:#1a1a1a;font-size:15px;margin:0 0 12px">Your verification code is:</p>
    <div style="text-align:center;background:#fff;border:1px solid #e6dfd0;border-radius:8px;padding:18px;margin:0 0 16px">
      <span style="font-size:34px;font-weight:bold;letter-spacing:10px;color:#7E2D49">${code}</span>
    </div>
    <p style="color:#707070;font-size:13px;margin:0 0 6px">This code is valid for 10 minutes. Do not share it with anyone.</p>
    <p style="color:#a8a8a8;font-size:12px;margin:16px 0 0">If you didn't request this, you can safely ignore this email.</p>
  </div>`;

  try {
    const res = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'api-key': apiKey,
        'content-type': 'application/json',
        'accept': 'application/json',
      },
      body: JSON.stringify({
        sender: SENDER,
        to: [{ email: to }],
        subject: 'Your Laxuage verification code',
        htmlContent: html,
      }),
    });
    return res.ok;
  } catch (e) {
    return false;
  }
}
