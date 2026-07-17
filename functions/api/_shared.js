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

// Simple KV-backed rolling rate limiter. Returns true if the call is allowed,
// false once `max` calls happen inside `windowSec`. Fails OPEN (returns true)
// if KV is unavailable, so a KV hiccup never blocks real customers.
export async function rateLimit(env, key, max, windowSec) {
  if (!env || !env.OTP_KV) return true;
  try {
    const k = 'rl:' + key;
    const n = parseInt((await env.OTP_KV.get(k)) || '0', 10);
    if (n >= max) return false;
    await env.OTP_KV.put(k, String(n + 1), { expirationTtl: windowSec });
    return true;
  } catch (e) { return true; }
}

// Read-only check: is this key already at its cap? Does NOT increment, so a
// caller can gate on a budget it only intends to charge conditionally (e.g.
// charge failed logins but not successful ones). Fails OPEN like rateLimit().
export async function rateLimitPeek(env, key, max) {
  if (!env || !env.OTP_KV) return false;
  try {
    const n = parseInt((await env.OTP_KV.get('rl:' + key)) || '0', 10);
    return n >= max;
  } catch (e) { return false; }
}

// The caller's IP (Cloudflare-provided; not spoofable by the client).
export function clientIp(request) {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}

// CSRF defence-in-depth: returns false only when the request clearly comes from
// a DIFFERENT origin (Origin/Referer host mismatch). Same-origin requests and
// clients that send neither header pass, so it never breaks legitimate use.
export function sameOrigin(request) {
  try {
    const host = request.headers.get('Host');
    const origin = request.headers.get('Origin');
    if (origin) return new URL(origin).host === host;
    const ref = request.headers.get('Referer');
    if (ref) return new URL(ref).host === host;
    return true; // neither header present — don't hard-block
  } catch (e) { return false; }
}

// Neutralise stored text so it can never become HTML/script in any render path,
// and strip control characters. Used for user-submitted review/name fields.
export function sanitizeText(s, max) {
  return String(s || '')
    .replace(/[\x00-\x1f\x7f]/g, ' ')
    .replace(/[<>]/g, '')
    .trim()
    .slice(0, max || 800);
}

// Escape the cookie name so a caller can never inject regex metacharacters.
function reEsc(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

export function getCookie(request, name) {
  const all = getCookies(request, name);
  return all.length ? all[0] : '';
}

// ALL values sent for `name`. A browser can send duplicates for the same name
// (e.g. a host-only cookie and a Domain=.laxuage.com cookie), and getCookie()
// only ever sees the first. Logout must clear every one of them, or the session
// whose token lost the race stays alive in KV.
export function getCookies(request, name) {
  const c = request.headers.get('Cookie') || '';
  const re = new RegExp('(?:^|;\\s*)' + reEsc(name) + '=([^;]*)', 'g');
  const out = [];
  let m;
  while ((m = re.exec(c)) !== null) if (m[1]) out.push(m[1]);
  return out;
}

// Admin sessions carry their issue time so that a password reset can revoke
// every existing session at once (there is no reverse token index in KV).
// Any session issued before `admin_sess_epoch` is dead.
export async function isAdmin(env, request) {
  if (!env.OTP_KV) return false;
  const token = getCookie(request, 'lax_admin');
  if (!token) return false;
  const val = await env.OTP_KV.get('adminsess:' + token);
  if (!val) return false;
  // Fail CLOSED: if the epoch cannot be read we cannot know whether this
  // session was revoked, and a revoked admin session must never be resurrected
  // by a D1 hiccup. The panel needs D1 for every screen anyway, so refusing
  // here costs no working functionality.
  let epoch = 0;
  try {
    const s = await getSettingStrict(env.DB, 'admin_sess_epoch');
    if (s && s.at) epoch = s.at;
  } catch (e) {
    return false;
  }
  const issued = parseInt(val, 10) || 0;   // legacy sessions stored '1'
  return issued >= epoch;
}

// ---- Admin password: env secret + D1 override ----
// ADMIN_PASSWORD is a Cloudflare env var, and a Worker cannot rewrite its own
// env — so "forgot password" stores a PBKDF2 hash in D1 (settings.admin_password)
// which, once present, takes precedence over the env secret.
// THROWS on a D1 read error — callers must surface that as "try again", never
// as a wrong password. Using the error-swallowing getSetting() here would make
// "override missing" and "read failed" indistinguishable, so a transient D1
// blip would silently re-enable a retired (possibly leaked) env password.
export async function verifyAdminPassword(env, pw) {
  const override = await getSettingStrict(env.DB, 'admin_password');
  if (override && override.hash) return await verifyPassword(pw, override.hash);
  const expected = env.ADMIN_PASSWORD;
  if (!expected) return false;
  return timingSafeEqual(pw, expected);
}

export async function setAdminPassword(env, pw) {
  const hash = await hashPassword(pw);
  await setSetting(env.DB, 'admin_password', { hash, at: Date.now() });
  // Revoke every admin session issued before now (see isAdmin).
  await setSetting(env.DB, 'admin_sess_epoch', { at: Date.now() });
}

// Constant-time string compare. Folds the length difference into the same
// accumulator instead of returning early on a length mismatch.
export function timingSafeEqual(a, b) {
  a = String(a); b = String(b);
  let diff = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}

// "adhur@gmail.com" -> "a***r@gmail.com" — enough for the owner to recognise
// the inbox, not enough to disclose it to a stranger.
export function maskEmail(email) {
  const s = String(email || '');
  const at = s.indexOf('@');
  if (at < 1) return '***';
  const user = s.slice(0, at), dom = s.slice(at);
  if (user.length <= 2) return user[0] + '***' + dom;
  return user[0] + '***' + user[user.length - 1] + dom;
}

// Build the customer-session Set-Cookie header. On *.laxuage.com hosts the
// cookie is scoped to ".laxuage.com" so the login is shared between
// laxuage.com and app.laxuage.com; on preview/localhost it stays host-only.
export function sessionCookie(request, token, ttl) {
  let host = '';
  try { host = new URL(request.url).hostname; } catch (e) {}
  const domain = /(^|\.)laxuage\.com$/i.test(host) ? '; Domain=.laxuage.com' : '';
  const tail = token ? '; Max-Age=' + ttl : '; Max-Age=0';
  return 'lax_session=' + (token || '') + '; HttpOnly; Secure; SameSite=Lax; Path=/' + domain + tail;
}

// Mint a customer session token. The stored value records WHEN it was issued so
// that a password reset can invalidate every older session for that user.
export async function createUserSession(env, userId, ttl) {
  const token = genToken();
  await env.OTP_KV.put('usersess:' + token, JSON.stringify({ uid: userId, iat: Date.now() }), { expirationTtl: ttl });
  return token;
}

// Returns the logged-in customer { id, email, name, phone } or null.
export async function getSessionUser(env, request) {
  if (!env.OTP_KV || !env.DB) return null;
  const token = getCookie(request, 'lax_session');
  if (!token) return null;
  const raw = await env.OTP_KV.get('usersess:' + token);
  if (!raw) return null;

  // New sessions are {uid,iat} JSON; legacy ones are a bare user-id string.
  let uid = 0, iat = 0;
  if (raw.charAt(0) === '{') {
    try { const p = JSON.parse(raw); uid = parseInt(p.uid, 10) || 0; iat = p.iat || 0; } catch (e) { return null; }
  } else {
    uid = parseInt(raw, 10) || 0;
  }
  if (!uid) return null;

  let u = null;
  try {
    u = await env.DB.prepare('SELECT id,email,name,phone,pw_changed_at FROM users WHERE id=?').bind(uid).first();
  } catch (e) {
    // pw_changed_at is added by ensureSchema, which does NOT run on read-only
    // paths like /api/auth/me. Immediately after this deploys the column does
    // not exist yet, and D1 fails the whole SELECT with "no such column" —
    // which would read as "no session" and log EVERY customer out until someone
    // happened to hit a route that migrates. Fall back to the pre-migration
    // shape instead.
    try {
      u = await env.DB.prepare('SELECT id,email,name,phone FROM users WHERE id=?').bind(uid).first();
    } catch (e2) {
      return null; // users table genuinely unavailable
    }
  }
  if (!u) return null;

  // Revoke sessions minted before the last password change. Legacy sessions
  // (iat=0) are only cut off once a password change actually happens.
  if (u.pw_changed_at && iat < u.pw_changed_at) {
    try { await env.OTP_KV.delete('usersess:' + token); } catch (e) {}
    return null;
  }
  return { id: u.id, email: u.email, name: u.name, phone: u.phone };
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
      status TEXT DEFAULT 'new',
      courier TEXT, tracking_no TEXT
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
    db.prepare(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE,
      name TEXT,
      phone TEXT,
      password_hash TEXT,
      created_at INTEGER,
      last_login INTEGER
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS user_data (
      user_id INTEGER PRIMARY KEY,
      cart TEXT,
      wishlist TEXT,
      updated_at INTEGER
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT, price INTEGER, mrp INTEGER,
      description TEXT, category TEXT, material TEXT, color TEXT,
      weight_g INTEGER, size TEXT,
      badge TEXT, rating REAL, reviews INTEGER,
      stock INTEGER,
      images TEXT,
      colors TEXT,
      active INTEGER DEFAULT 1,
      sort_order INTEGER DEFAULT 0,
      created_at INTEGER
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT,
      updated_at INTEGER
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS subscribers (
      email TEXT PRIMARY KEY,
      created_at INTEGER,
      source TEXT
    )`),
  ]);
  // Column migrations for older tables (ignored if the column already exists).
  try { await db.prepare('ALTER TABLE products ADD COLUMN colors TEXT').run(); } catch (e) {}
  try { await db.prepare('ALTER TABLE users ADD COLUMN password_hash TEXT').run(); } catch (e) {}
  try { await db.prepare('ALTER TABLE users ADD COLUMN pw_changed_at INTEGER').run(); } catch (e) {}
  try { await db.prepare('ALTER TABLE orders ADD COLUMN rp_order_id TEXT').run(); } catch (e) {}
  try { await db.prepare('ALTER TABLE orders ADD COLUMN courier TEXT').run(); } catch (e) {}
  try { await db.prepare('ALTER TABLE orders ADD COLUMN tracking_no TEXT').run(); } catch (e) {}
}

// ---- Password hashing (PBKDF2-SHA256, salted) ----
function buf2hex(buf) { return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join(''); }
function hex2buf(hex) { const a = new Uint8Array(hex.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(hex.substr(i * 2, 2), 16); return a; }

export async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return 'pbkdf2$100000$' + buf2hex(salt.buffer) + '$' + buf2hex(bits);
}

export async function verifyPassword(password, stored) {
  if (!stored || typeof stored !== 'string') return false;
  const parts = stored.split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const iterations = parseInt(parts[1], 10) || 100000;
  const salt = hex2buf(parts[2]);
  const expected = parts[3];
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, key, 256);
  const got = buf2hex(bits);
  if (got.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < got.length; i++) diff |= got.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

// ---- OTP email (Brevo) — used by signup email verification ----
export function genOTP() {
  // Rejection sampling removes the small modulo bias of a raw % 900000.
  const a = new Uint32Array(1);
  let v;
  do { crypto.getRandomValues(a); v = a[0]; } while (v >= 4294800000); // floor(2^32/900000)*900000
  return String(100000 + (v % 900000));
}

// Sends a 6-digit code. `opts` lets callers retitle it for a different purpose
// (e.g. an admin password reset); defaults keep the original signup wording, so
// existing callers are unaffected. Returns true only if Brevo accepted it.
export async function sendOtpEmail(apiKey, to, code, opts) {
  const o = opts || {};
  const subject = o.subject || 'Your Laxuage verification code';
  const intro = o.intro || 'Your email verification code is:';
  const footer = o.footer || "If you didn't request this, you can safely ignore this email.";
  const html = `
  <div style="font-family:Arial,Helvetica,sans-serif;max-width:480px;margin:0 auto;background:#fbf7f1;padding:32px 24px;border-radius:8px">
    <div style="text-align:center;margin-bottom:24px">
      <span style="font-family:Georgia,serif;font-size:26px;font-style:italic;color:#7E2D49;letter-spacing:1px">Laxuage</span>
      <div style="font-size:11px;letter-spacing:3px;color:#b08d57;text-transform:uppercase;margin-top:2px">Made of Her</div>
    </div>
    <p style="color:#1a1a1a;font-size:15px;margin:0 0 12px">${intro}</p>
    <div style="text-align:center;background:#fff;border:1px solid #e6dfd0;border-radius:8px;padding:18px;margin:0 0 16px">
      <span style="font-size:34px;font-weight:bold;letter-spacing:10px;color:#7E2D49">${code}</span>
    </div>
    <p style="color:#707070;font-size:13px;margin:0 0 6px">This code is valid for 10 minutes. Do not share it with anyone.</p>
    <p style="color:#a8a8a8;font-size:12px;margin:16px 0 0">${footer}</p>
  </div>`;
  try {
    const res = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'api-key': apiKey, 'content-type': 'application/json', 'accept': 'application/json' },
      body: JSON.stringify({ sender: { name: 'Laxuage', email: 'support@laxuage.com' }, to: [{ email: to }], subject, htmlContent: html }),
    });
    return res.ok;
  } catch (e) { return false; }
}

// Read a JSON setting by key. Returns null both when the key is absent AND when
// the read fails — convenient, but it means callers cannot tell those apart.
// For anything security-critical use getSettingStrict().
export async function getSetting(db, key) {
  try {
    return await getSettingStrict(db, key);
  } catch (e) { return null; }
}

// Same, but propagates read errors instead of swallowing them. Returns null ONLY
// when the key genuinely does not exist.
export async function getSettingStrict(db, key) {
  if (!db) throw new Error('D1 binding "DB" missing');
  const row = await db.prepare('SELECT value FROM settings WHERE key=?').bind(key).first();
  if (!row || !row.value) return null;
  try {
    return JSON.parse(row.value);
  } catch (e) {
    throw new Error('settings.' + key + ' is not valid JSON');
  }
}

// Write a JSON setting by key (upsert).
export async function setSetting(db, key, obj) {
  await db.prepare(
    `INSERT INTO settings (key, value, updated_at) VALUES (?,?,?)
     ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`
  ).bind(key, JSON.stringify(obj), Date.now()).run();
}

// The original 9 catalogue items — used to seed the products table the first
// time (so the store keeps working) and as the storefront fallback.
export const SEED_PRODUCTS = [
  { id:1, name:"Ivory Chain Shoulder Bag", price:1599, mrp:2499, images:["bag1.jpg"], description:"Elegant ivory leather bag with bold gold chain strap and signature clasp. Perfect for daily elegance and evening outings.", category:"handbag", badge:"new", rating:4.5, reviews:128, color:"Ivory", material:"Vegan Leather", weight_g:650, size:"28 × 18 × 10 cm", stock:6 },
  { id:2, name:"Quilted White Crossbody", price:1497, mrp:2299, images:["bag2.jpg"], description:"Luxurious quilted white crossbody with beautiful gold flower emblem. Spacious and stylish for casual and formal use.", category:"crossbody", badge:"hot", rating:4.7, reviews:96, color:"White", material:"Quilted Faux Leather", weight_g:520, size:"24 × 16 × 8 cm", stock:4 },
  { id:3, name:"Beige Monogram Satchel", price:1497, mrp:2199, images:["bag3.jpg"], description:"Sophisticated beige and white patterned satchel with adjustable strap. Classic design with modern comfort.", category:"handbag", badge:"", rating:4.3, reviews:74, color:"Beige", material:"Monogram Canvas", weight_g:700, size:"30 × 20 × 12 cm", stock:12 },
  { id:4, name:"Black Pleated Tote Bag", price:1397, mrp:2099, images:["bag4.jpg"], description:"Chic black pleated tote with structured design. Spacious interior perfect for office and weekend use.", category:"tote", badge:"exclusive", rating:4.6, reviews:112, color:"Black", material:"Pleated PU", weight_g:780, size:"34 × 28 × 12 cm", stock:9 },
  { id:5, name:"Cream Star Chain Bag", price:1597, mrp:2399, images:["bag5.jpg"], description:"Premium cream leather bag with gold chain and star charm detail. A true statement piece.", category:"handbag", badge:"new", rating:4.8, reviews:203, color:"Cream", material:"Vegan Leather", weight_g:600, size:"26 × 17 × 9 cm", stock:3 },
  { id:6, name:"White Quilted Mini Bag", price:1899, mrp:2799, images:["bag6.jpg"], description:"Adorable white quilted mini bag with gold clover emblem. Compact yet stylish for everyday essentials.", category:"crossbody", badge:"hot", rating:4.4, reviews:88, color:"White", material:"Quilted Faux Leather", weight_g:400, size:"20 × 14 × 7 cm", stock:7 },
  { id:7, name:"Dual Tone Beige Set", price:1497, mrp:2299, images:["bag7.jpg"], description:"Elegant beige collection featuring textured and patterned designs. Versatile and luxurious.", category:"handbag", badge:"", rating:4.5, reviews:61, color:"Beige", material:"Textured PU", weight_g:720, size:"29 × 19 × 11 cm", stock:10 },
  { id:8, name:"Brown Leather Crossbody", price:1599, mrp:2499, images:["bag8.jpg"], description:"Rich brown leather crossbody with gold hardware and signature logo. Timeless and sophisticated.", category:"crossbody", badge:"exclusive", rating:4.6, reviews:145, color:"Brown", material:"Vegan Leather", weight_g:540, size:"25 × 16 × 8 cm", stock:5 },
  { id:9, name:"Pearl & Gold Clutch Set", price:1597, mrp:2599, images:["bag9.jpg"], description:"Stunning handcrafted pearl and gold beaded clutches. Perfect for parties and special occasions.", category:"clutch", badge:"new", rating:4.9, reviews:77, color:"Gold", material:"Pearl & Beadwork", weight_g:320, size:"22 × 12 × 5 cm", stock:2 },
];

// Seed the products table once (only if empty).
export async function seedProductsIfEmpty(db) {
  const row = await db.prepare('SELECT COUNT(*) AS c FROM products').first();
  if (row && row.c > 0) return;
  const now = Date.now();
  const stmts = SEED_PRODUCTS.map((p, i) => db.prepare(
    `INSERT INTO products (id,name,price,mrp,description,category,material,color,weight_g,size,badge,rating,reviews,stock,images,active,sort_order,created_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)`
  ).bind(p.id, p.name, p.price, p.mrp, p.description, p.category, p.material, p.color, p.weight_g, p.size, p.badge, p.rating, p.reviews, p.stock, JSON.stringify(p.images), i, now));
  await db.batch(stmts);
}

// Normalise a DB product row into the shape the storefront expects.
export function rowToProduct(r) {
  let images = [];
  try { images = JSON.parse(r.images || '[]'); } catch (e) {}
  let colors = [];
  try { colors = JSON.parse(r.colors || '[]'); } catch (e) {}
  colors = Array.isArray(colors) ? colors.filter(c => c && c.name) : [];
  const colorImg = colors.find(c => c.image) ? colors.find(c => c.image).image : '';
  return {
    id: r.id, name: r.name, price: r.price, mrp: r.mrp,
    description: r.description, category: r.category, material: r.material,
    color: r.color || (colors[0] && colors[0].name) || '',
    colors,
    weight_g: r.weight_g, size: r.size, badge: r.badge || '',
    rating: r.rating, reviews: r.reviews, stock: r.stock,
    images, img: images[0] || colorImg || '',
  };
}
