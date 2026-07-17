// POST /api/admin/logout  -> clears the admin session
import { json, getCookies } from '../_shared.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  // Clear every lax_admin cookie the browser sent, not just the first (see
  // the customer logout for the duplicate-cookie case).
  const tokens = getCookies(request, 'lax_admin');
  if (env.OTP_KV) {
    for (const t of tokens) {
      try { await env.OTP_KV.delete('adminsess:' + t); } catch (e) {}
    }
  }
  return json({ ok: true }, 200, {
    'Set-Cookie': 'lax_admin=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0',
  });
}
