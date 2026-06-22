// GET  /api/admin/showcase  -> current showcase config (admin)
// POST /api/admin/showcase  { mode, title, banner, videos, productIds, autoplay }
// Saves the homepage showcase config. Gated by /api/admin/_middleware.js.
import { json, ensureSchema, getSetting, setSetting } from '../_shared.js';
import { DEFAULT_SHOWCASE } from '../showcase.js';

export async function onRequestGet(context) {
  const { env } = context;
  await ensureSchema(env.DB);
  const cfg = await getSetting(env.DB, 'showcase');
  return json({ ok: true, showcase: cfg || DEFAULT_SHOWCASE });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  await ensureSchema(env.DB);

  let b;
  try { b = await request.json(); } catch (e) { return json({ ok: false, error: 'Bad request' }, 400); }

  const mode = ['banner', 'videos', 'products'].includes(b.mode) ? b.mode : 'products';
  const s = v => String(v == null ? '' : v);

  const cfg = {
    mode,
    title: s(b.title || 'Featured Collection').slice(0, 80),
    banner: (b.banner && typeof b.banner === 'object' && b.banner.image)
      ? { image: s(b.banner.image).slice(0, 400), link: s(b.banner.link).slice(0, 400), caption: s(b.banner.caption).slice(0, 140) }
      : null,
    videos: Array.isArray(b.videos)
      ? b.videos.map(s).map(v => v.trim()).filter(Boolean).slice(0, 3).map(v => v.slice(0, 500))
      : [],
    productIds: Array.isArray(b.productIds)
      ? Array.from(new Set(b.productIds.map(x => parseInt(x, 10)).filter(n => n > 0))).slice(0, 12)
      : [],
    autoplay: b.autoplay !== false,
  };

  await setSetting(env.DB, 'showcase', cfg);
  return json({ ok: true, showcase: cfg });
}
