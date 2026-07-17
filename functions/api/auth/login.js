// POST /api/auth/login  { email, password }
// Verifies the password and issues a 30-day session cookie.
import { json, ensureSchema, verifyPassword, sessionCookie, createUserSession, clientIp, rateLimit, rateLimitPeek } from '../_shared.js';

const SESSION_TTL = 30 * 24 * 60 * 60; // 30 days
const MAX_FAILS = 8;                   // wrong passwords per (email+IP) before lockout
const LOCK_SECS = 900;                 // 15 min
const IP_MAX = 50;                     // FAILED logins per IP …
const IP_WINDOW = 900;                 // … per 15 min

// Every failure path returns THIS. Distinct "no such account" / "no password
// yet" / "wrong password" replies turned the login form into an oracle for
// which emails are registered — which defeated the whole point of
// forgot-password.js deliberately not leaking that. Recovery for every case
// (including legacy accounts with no password) is "Forgot password".
const GENERIC = 'Incorrect email or password.';

// Keyed by email AND IP, deliberately. A pure per-email lock would hand anyone
// a remote denial-of-service: 8 wrong guesses would lock a customer out of
// their own account for 15 minutes from anywhere in the world. Scoping to the
// attacker's own IP keeps targeted brute force bounded while leaving the real
// customer — on a different IP — able to sign in normally. Distributed guessing
// is bounded instead by the per-IP failure cap below.
const failKeyFor = (email, ip) => 'loginfail:' + ip + ':' + email;

async function readFails(env, email, ip) {
  try {
    const raw = await env.OTP_KV.get(failKeyFor(email, ip));
    if (!raw) return { n: 0, until: 0 };
    const p = JSON.parse(raw);
    return { n: parseInt(p.n, 10) || 0, until: parseInt(p.until, 10) || 0 };
  } catch (e) { return { n: 0, until: 0 }; }
}

async function noteFail(env, email, ip, rec) {
  const n = rec.n + 1;
  const until = n >= MAX_FAILS ? Date.now() + LOCK_SECS * 1000 : 0;
  try {
    await env.OTP_KV.put(failKeyFor(email, ip), JSON.stringify({ n, until }), {
      expirationTtl: Math.max(IP_WINDOW, LOCK_SECS + 60),
    });
  } catch (e) {}
  return until;
}

export async function onRequestPost(context) {
  const { request, env } = context;
  if (!env.OTP_KV) return json({ ok: false, error: 'Server not configured.' }, 500);
  try { await ensureSchema(env.DB); } catch (e) {
    return json({ ok: false, error: 'Server storage unavailable. Please try again.' }, 500);
  }

  let b;
  try { b = await request.json(); } catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }
  const email = String(b.email || '').trim().toLowerCase();
  const password = String(b.password || '');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || !password) {
    return json({ ok: false, error: 'Enter your email and password.' }, 400);
  }

  // The (email+IP) lockout stops a targeted brute force; the per-IP failure cap
  // stops one host spraying many accounts. Neither existed before — the
  // endpoint accepted unlimited guesses at full speed.
  const ip = clientIp(request);
  const rec = await readFails(env, email, ip);
  if (rec.until > Date.now()) {
    const secs = Math.ceil((rec.until - Date.now()) / 1000);
    return json(
      { ok: false, error: 'Too many failed attempts. Please try again in a few minutes, or reset your password.', locked: true, retry_after: secs },
      429, { 'Retry-After': String(secs) }
    );
  }
  // NB: checked but NOT charged here. The budget is charged only on the failure
  // path below — counting successes too would let a busy office or mobile
  // carrier NAT (many customers, one IP) lock its own users out by simply
  // shopping normally.
  const ipKey = 'loginip:' + ip;
  if (await rateLimitPeek(env, ipKey, IP_MAX)) {
    return json({ ok: false, error: 'Too many failed login attempts from this network. Please try again later.' }, 429);
  }

  const user = await env.DB.prepare('SELECT id,email,name,phone,password_hash FROM users WHERE email=?').bind(email).first();

  // Same reply whether or not the account exists.
  if (!user || !user.password_hash || !(await verifyPassword(password, user.password_hash))) {
    await rateLimit(env, ipKey, IP_MAX, IP_WINDOW);   // charge failures only
    const until = await noteFail(env, email, ip, rec);
    if (until) {
      const secs = Math.ceil((until - Date.now()) / 1000);
      return json(
        { ok: false, error: 'Too many failed attempts. Please try again in a few minutes, or reset your password.', locked: true, retry_after: secs },
        429, { 'Retry-After': String(secs) }
      );
    }
    return json({ ok: false, error: GENERIC }, 401);
  }

  try { await env.OTP_KV.delete(failKeyFor(email, ip)); } catch (e) {} // reset on success

  await env.DB.prepare('UPDATE users SET last_login=? WHERE id=?').bind(Date.now(), user.id).run();
  const token = await createUserSession(env, user.id, SESSION_TTL);

  return json({ ok: true, user: { id: user.id, email: user.email, name: user.name, phone: user.phone } }, 200, {
    'Set-Cookie': sessionCookie(request, token, SESSION_TTL),
  });
}
