// GET /api/admin/stats -> dashboard summary
import { json, ensureSchema } from '../_shared.js';

export async function onRequestGet(context) {
  const { env } = context;
  await ensureSchema(env.DB);
  const db = env.DB;
  const orders = await db.prepare('SELECT COUNT(*) AS c FROM orders').first();
  const revenue = await db.prepare("SELECT COALESCE(SUM(total),0) AS s FROM orders WHERE payment_status='paid' OR payment_method='cod'").first();
  const pending = await db.prepare("SELECT COUNT(*) AS c FROM orders WHERE status='new'").first();
  const delivered = await db.prepare("SELECT COUNT(*) AS c FROM orders WHERE status='delivered'").first();
  const pendingReviews = await db.prepare('SELECT COUNT(*) AS c FROM reviews WHERE approved=0').first();
  const lowStock = await db.prepare('SELECT COUNT(*) AS c FROM products WHERE stock IS NOT NULL AND stock<=4 AND active=1').first();
  return json({
    ok: true,
    stats: {
      orders: (orders && orders.c) || 0,
      revenue: (revenue && revenue.s) || 0,
      pendingOrders: (pending && pending.c) || 0,
      delivered: (delivered && delivered.c) || 0,
      pendingReviews: (pendingReviews && pendingReviews.c) || 0,
      lowStock: (lowStock && lowStock.c) || 0,
    },
  });
}
