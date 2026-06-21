// Shared helpers for Laxuage API functions (D1 + admin auth).
// Underscore-prefixed → not a route; imported by other functions.

export function json(obj, status = 200, extraHeaders) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: Object.assign({ 'content-type': 'application/json' }, extraHeaders || {}),
  });
}

export function genToken() {
  const a = new Uint8Array(24);
  crypto.getRandomValues(a);
  return Array.from(a).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function getCookie(request, name) {
  const c = request.headers.get('Cookie') || '';
  const m = c.match(new RegExp('(?:^|; )' + name + '=([^;]+)'));
  return m ? m[1] : '';
}

export async function isAdmin(env, request) {
  if (!env.OTP_KV) return false;
  const token = getCookie(request, 'lax_admin');
  if (!token) return false;
  return !!(await env.OTP_KV.get('adminsess:' + token));
}

// Idempotent schema creation. Cheap (CREATE TABLE IF NOT EXISTS); safe to call per request.
export async function ensureSchema(db) {
  if (!db) throw new Error('D1 binding "DB" missing');
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS orders (
      id TEXT PRIMARY KEY,
      created_at INTEGER NOT NULL,
      customer_name TEXT, customer_phone TEXT, customer_email TEXT, address TEXT,
      items TEXT,
      subtotal INTEGER, shipping INTEGER, total INTEGER,
      payment_method TEXT, payment_id TEXT, payment_status TEXT,
      status TEXT DEFAULT 'new'
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS stock (
      product_id INTEGER PRIMARY KEY,
      stock INTEGER NOT NULL DEFAULT 0,
      price INTEGER,
      updated_at INTEGER
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER,
      name TEXT, rating INTEGER, text TEXT,
      created_at INTEGER,
      approved INTEGER DEFAULT 0
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS coupons (
      code TEXT PRIMARY KEY,
      type TEXT, value INTEGER,
      active INTEGER DEFAULT 1,
      min_order INTEGER DEFAULT 0
    )`),
  ]);
}
