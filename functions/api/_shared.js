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

// Returns the logged-in customer { id, email, name, phone } or null.
export async function getSessionUser(env, request) {
  if (!env.OTP_KV || !env.DB) return null;
  const token = getCookie(request, 'lax_session');
  if (!token) return null;
  const uid = await env.OTP_KV.get('usersess:' + token);
  if (!uid) return null;
  try {
    const u = await env.DB.prepare('SELECT id,email,name,phone FROM users WHERE id=?').bind(parseInt(uid, 10)).first();
    return u || null;
  } catch (e) {
    return null; // users table may not exist yet
  }
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
    db.prepare(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE,
      name TEXT,
      phone TEXT,
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
      active INTEGER DEFAULT 1,
      sort_order INTEGER DEFAULT 0,
      created_at INTEGER
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT,
      updated_at INTEGER
    )`),
  ]);
}

// Read a JSON setting by key (returns parsed object or null).
export async function getSetting(db, key) {
  try {
    const row = await db.prepare('SELECT value FROM settings WHERE key=?').bind(key).first();
    if (row && row.value) return JSON.parse(row.value);
  } catch (e) {}
  return null;
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
  return {
    id: r.id, name: r.name, price: r.price, mrp: r.mrp,
    description: r.description, category: r.category, material: r.material, color: r.color,
    weight_g: r.weight_g, size: r.size, badge: r.badge || '',
    rating: r.rating, reviews: r.reviews, stock: r.stock,
    images, img: images[0] || '',
  };
}
