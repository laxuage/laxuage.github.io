// Auth gate for every /api/admin/* route except login.
import { json, isAdmin } from '../_shared.js';

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  if (url.pathname === '/api/admin/login') return next();   // login is public
  if (request.method === 'OPTIONS') return next();
  if (!(await isAdmin(env, request))) {
    return json({ ok: false, error: 'Unauthorized' }, 401);
  }
  return next();
}
