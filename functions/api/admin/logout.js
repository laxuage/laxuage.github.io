// POST /api/admin/logout  -> clears the admin session
import { json, getCookie } from '../_shared.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  const token = getCookie(request, 'lax_admin');
  if (token) { try { await env.OTP_KV.delete('adminsess:' + token); } catch (e) {} }
  return json({ ok: true }, 200, {
    'Set-Cookie': 'lax_admin=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0',
  });
}
