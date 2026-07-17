// POST /api/admin/login  { password }  -> sets HttpOnly admin session cookie
// GET  /api/admin/login              -> { locked, retry_after } so the panel can
//                                        render an accurate countdown on load.
import { json, genToken, ensureSchema, verifyAdminPassword, clientIp, getSetting } from '../_shared.js';

const SESSION_TTL = 24 * 60 * 60; // 1 day (shorter window if a token ever leaks)
const MAX_FAILS = 5;              // wrong passwords allowed before the IP locks
const STEP_SECS = 180;            // 1st lock 3 min, then 6, 9, 12, 15 …
const MAX_LOCK = 3600;            // … capped at 1 hour
const WINDOW = 1200;              // failures are forgotten after 20 min of quiet

const failKeyFor = ip => 'adminfail:' + ip;

// Read the {n, until} failure record. Returns null when absent/unreadable.
async function readFails(env, ip) {
  try {
    const raw = await env.OTP_KV.get(failKeyFor(ip));
    if (!raw) return null;
    if (raw.charAt(0) !== '{') return { n: parseInt(raw, 10) || 0, until: 0 }; // legacy counter
    const p = JSON.parse(raw);
    return { n: parseInt(p.n, 10) || 0, until: parseInt(p.until, 10) || 0 };
  } catch (e) { return null; }
}

// Seconds still to wait, or 0 when not locked.
const remaining = rec => (rec && rec.until > Date.now() ? Math.ceil((rec.until - Date.now()) / 1000) : 0);

function lockedResponse(secs) {
  return json(
    { ok: false, error: 'Too many failed attempts.', locked: true, retry_after: secs },
    429,
    { 'Retry-After': String(secs) }
  );
}

// Current lock state, so the panel's countdown reflects the SERVER's clock
// rather than a guess in localStorage.
export async function onRequestGet(context) {
  const { request, env } = context;
  if (!env.OTP_KV) return json({ ok: true, locked: false, retry_after: 0 });
  const rec = await readFails(env, clientIp(request));
  const secs = remaining(rec);
  return json({ ok: true, locked: secs > 0, retry_after: secs });
}

export async function onRequestPost(context) {
  const { request, env } = context;

  const ip = clientIp(request);
  const rec = (await readFails(env, ip)) || { n: 0, until: 0 };

  // Already locked — report exactly how long is left, and do NOT extend the
  // lock, or a bot hammering the endpoint could keep the owner out forever.
  const left = remaining(rec);
  if (left > 0) return lockedResponse(left);

  let pw = '';
  try { pw = String((await request.json()).password || ''); }
  catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }

  // A D1 read failure must NOT be counted as a wrong password — that would
  // march the owner toward a lockout for an outage they did not cause, and
  // (worse) silently accept a retired env password. Fail loudly, charge nothing.
  let ok;
  try {
    ok = await verifyAdminPassword(env, pw);
  } catch (e) {
    return json({ ok: false, error: 'Sign-in is temporarily unavailable. Please try again in a moment.' }, 503);
  }

  // Only fatal once we know there is neither an override nor an env secret.
  if (!ok && !env.ADMIN_PASSWORD) {
    let hasOverride = false;
    try { const o = await getSetting(env.DB, 'admin_password'); hasOverride = !!(o && o.hash); } catch (e) {}
    if (!hasOverride) return json({ ok: false, error: 'Admin not configured (set ADMIN_PASSWORD).' }, 500);
  }

  if (!ok) {
    const n = rec.n + 1;
    let until = 0, secs = 0;
    if (n >= MAX_FAILS) {
      // Escalates for real: the old code returned before this increment, so the
      // window could never grow past the first step.
      secs = Math.min(MAX_LOCK, STEP_SECS * (n - MAX_FAILS + 1)); // 3,6,9,12,15 … min
      until = Date.now() + secs * 1000;
    }
    try {
      await env.OTP_KV.put(failKeyFor(ip), JSON.stringify({ n, until }), {
        expirationTtl: Math.max(WINDOW, secs + 60),
      });
    } catch (e) {}
    // The attempt that TRIPS the lock must report the lock too. Previously it
    // returned a plain 401, so the panel only discovered the lock on the NEXT
    // attempt and anchored its countdown a step late.
    if (secs > 0) return lockedResponse(secs);
    return json({ ok: false, error: 'Wrong password', attempts_left: MAX_FAILS - n }, 401);
  }

  try { await env.OTP_KV.delete(failKeyFor(ip)); } catch (e) {} // reset on success

  const token = genToken();
  // Value = issue time, so a password reset can revoke older sessions (isAdmin).
  await env.OTP_KV.put('adminsess:' + token, String(Date.now()), { expirationTtl: SESSION_TTL });
  try { await ensureSchema(env.DB); } catch (e) {}

  return json({ ok: true }, 200, {
    'Set-Cookie': 'lax_admin=' + token + '; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=' + SESSION_TTL,
  });
}
