// POST /api/admin/forgot  {}  -> emails a 6-digit reset code to the store owner.
//
// There is no admin "account" to look up: the panel is guarded by a single
// password, so the code always goes to one fixed owner mailbox. Set ADMIN_EMAIL
// in the Cloudflare Pages env to change the destination without a code change.
import { json, ensureSchema, genOTP, sendOtpEmail, rateLimit, clientIp, maskEmail } from '../_shared.js';

const TTL = 600;                  // reset code valid 10 min
const RESEND_COOLDOWN_MS = 45000; // 45s between sends
const KEY = 'adminreset';

// The owner's inbox. ADMIN_EMAIL wins; otherwise fall back to the Brevo-verified
// account address. NOTE: this must be a mailbox the owner actually reads.
export function adminEmail(env) {
  const e = String((env && env.ADMIN_EMAIL) || '').trim().toLowerCase();
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e) ? e : 'laxuage@gmail.com';
}

export async function onRequestPost(context) {
  const { request, env } = context;
  if (!env.OTP_KV) return json({ ok: false, error: 'Server not configured (KV).' }, 500);
  if (!env.BREVO_API_KEY) return json({ ok: false, error: 'Password reset is unavailable: email is not configured on the server.' }, 500);
  try { await ensureSchema(env.DB); } catch (e) {}

  const to = adminEmail(env);

  // ORDER MATTERS. Everything that can reject a request cheaply runs BEFORE any
  // budget is charged, and the shared/global budget is charged LAST — only for
  // a request that will really send mail.
  //
  // Previously the global cap was consumed first, by every caller, including
  // ones the cooldown then silently no-op'd. Since /api/admin/forgot is public,
  // a stranger could spend the owner's whole recovery budget in one burst and
  // lock them out of the only way back into their own store.

  // 1. Per-IP first: an abusive IP can only ever exhaust its own allowance.
  if (!(await rateLimit(env, 'admresetip:' + clientIp(request), 5, 1800))) {
    return json({ ok: false, error: 'Too many reset requests from this network. Please try again in about 30 minutes.' }, 429);
  }

  // 2. Cooldown: costs no budget, sends no mail.
  const prevRaw = await env.OTP_KV.get(KEY);
  if (prevRaw) {
    try {
      const prev = JSON.parse(prevRaw);
      if (prev.sentAt && Date.now() - prev.sentAt < RESEND_COOLDOWN_MS) {
        const wait = Math.ceil((RESEND_COOLDOWN_MS - (Date.now() - prev.sentAt)) / 1000);
        return json({ ok: true, resent: false, email_hint: maskEmail(to), retry_after: wait });
      }
    } catch (e) {}
  }

  // 3. Global cap: a Brevo-quota/inbox-flood guard only, set well above any
  //    plausible owner need, and charged solely on the send path.
  if (!(await rateLimit(env, 'admreset', 30, 3600))) {
    return json({ ok: false, error: 'Too many reset requests. Please try again later.' }, 429);
  }

  const code = genOTP();
  const sent = await sendOtpEmail(env.BREVO_API_KEY, to, code, {
    subject: 'Your Laxuage admin password reset code',
    intro: 'Use this code to reset your Laxuage <b>admin panel</b> password:',
    footer: "If you didn't request this, someone may be trying to access your admin panel. You can ignore this email — your password has not changed.",
  });

  // Only persist the code once the mail actually went out, and surface a send
  // failure instead of stranding the owner on a code screen forever.
  if (!sent) return json({ ok: false, error: 'Could not send the email. Please try again in a minute.' }, 502);

  await env.OTP_KV.put(KEY, JSON.stringify({ code, sentAt: Date.now(), attempts: 0 }), { expirationTtl: TTL });
  return json({ ok: true, resent: true, email_hint: maskEmail(to) });
}
