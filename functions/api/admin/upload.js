// POST /api/admin/upload  (multipart form, field "file") -> stores image in R2
import { json, genToken } from '../_shared.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  if (!env.IMAGES) return json({ ok: false, error: 'Image storage (R2) not configured.' }, 500);

  let form;
  try { form = await request.formData(); } catch (e) { return json({ ok: false, error: 'Bad upload' }, 400); }
  const file = form.get('file');
  if (!file || typeof file === 'string') return json({ ok: false, error: 'No file received' }, 400);

  const type = file.type || 'image/jpeg';
  if (!/^image\//.test(type)) return json({ ok: false, error: 'Only image files are allowed.' }, 400);
  if (file.size > 5 * 1024 * 1024) return json({ ok: false, error: 'Image too large (max 5 MB).' }, 400);

  let ext = (type.split('/')[1] || 'jpg').toLowerCase().replace('jpeg', 'jpg').replace(/[^a-z0-9]/g, '').slice(0, 5);
  const key = 'p/' + Date.now().toString(36) + genToken().slice(0, 8) + '.' + ext;

  const buf = await file.arrayBuffer();
  await env.IMAGES.put(key, buf, { httpMetadata: { contentType: type } });

  return json({ ok: true, url: '/img/' + key, key });
}
