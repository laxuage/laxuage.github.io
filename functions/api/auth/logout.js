// POST /api/auth/logout -> clears the customer session
import { json, getCookie, sessionCookie } from '../_shared.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  const token = getCookie(request, 'lax_session');
  if (token) { try { await env.OTP_KV.delete('usersess:' + token); } catch (e) {} }
  return json({ ok: true }, 200, {
    'Set-Cookie': sessionCookie(request, '', 0),
  });
}
