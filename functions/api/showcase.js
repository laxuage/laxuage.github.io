// GET /api/showcase -> the homepage showcase config (public).
// Drives the hero carousel: a banner, 1-3 videos, or a set of products.
import { json, ensureSchema, getSetting } from './_shared.js';

export const DEFAULT_SHOWCASE = {
  mode: 'products',            // 'banner' | 'videos' | 'products'
  title: 'Featured Collection',
  banner: null,                // { image, link, caption }
  videos: [],                  // [url, url, url]  (YouTube / direct .mp4)
  productIds: [],              // [] = auto (first products); else these ids in order
  autoplay: true,
};

export async function onRequestGet(context) {
  const { env } = context;
  try { await ensureSchema(env.DB); } catch (e) {}
  let cfg = null;
  try { cfg = await getSetting(env.DB, 'showcase'); } catch (e) {}
  return json({ ok: true, showcase: cfg || DEFAULT_SHOWCASE });
}
