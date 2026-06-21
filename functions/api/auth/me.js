// GET /api/auth/me -> { ok:true, user } if logged in, else { ok:false }
import { json, getSessionUser } from '../_shared.js';

export async function onRequestGet(context) {
  const { request, env } = context;
  const user = await getSessionUser(env, request);
  if (!user) return json({ ok: false });
  return json({ ok: true, user });
}
