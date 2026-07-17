// POST /api/auth/logout -> clears the customer session
import { json, getCookies, sessionCookie } from '../_shared.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  // The browser can send MORE THAN ONE lax_session cookie (a host-only one and
  // the Domain=.laxuage.com one). Reading only the first left the other token
  // live in KV, so "sign out" didn't actually end that session.
  const tokens = getCookies(request, 'lax_session');
  if (env.OTP_KV) {
    for (const t of tokens) {
      try { await env.OTP_KV.delete('usersess:' + t); } catch (e) {}
    }
  }
  return json({ ok: true }, 200, {
    'Set-Cookie': sessionCookie(request, '', 0),
  });
}
