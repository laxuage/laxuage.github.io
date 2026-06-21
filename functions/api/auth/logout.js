// POST /api/auth/logout -> clears the customer session
import { json, getCookie } from '../_shared.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  const token = getCookie(request, 'lax_session');
  if (token) { try { await env.OTP_KV.delete('usersess:' + token); } catch (e) {} }
  return json({ ok: true }, 200, {
    'Set-Cookie': 'lax_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0',
  });
}
