// Auth gate for every /api/admin/* route except login.
import { json, isAdmin, sameOrigin } from '../_shared.js';

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  if (request.method === 'OPTIONS') return next();
  // CSRF defence-in-depth: block clearly cross-origin writes to admin routes
  // (on top of the SameSite=Strict admin cookie). Same-origin requests pass.
  if (request.method !== 'GET' && request.method !== 'HEAD' && !sameOrigin(request)) {
    return json({ ok: false, error: 'Cross-origin request blocked.' }, 403);
  }
  if (url.pathname === '/api/admin/login') return next();   // login is public
  if (!(await isAdmin(env, request))) {
    return json({ ok: false, error: 'Unauthorized' }, 401);
  }
  return next();
}
