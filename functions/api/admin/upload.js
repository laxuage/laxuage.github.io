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
  const isImage = /^image\//.test(type);
  const isVideo = /^video\//.test(type);
  if (!isImage && !isVideo) return json({ ok: false, error: 'Only image or video files are allowed.' }, 400);
  // Block SVG outright — it is an XSS vector (can carry <script>), not a raster image.
  if (/svg/i.test(type)) return json({ ok: false, error: 'SVG files are not allowed.' }, 400);
  const maxBytes = isVideo ? 40 * 1024 * 1024 : 5 * 1024 * 1024;
  if (file.size > maxBytes) return json({ ok: false, error: isVideo ? 'Video too large (max 40 MB) — use a YouTube link instead.' : 'Image too large (max 5 MB).' }, 400);

  const buf = await file.arrayBuffer();
  // Verify the REAL file bytes (not the client-declared type). This rejects a
  // .svg/.html/.js renamed as an image, closing the stored-XSS-via-upload path.
  const kind = sniffMedia(new Uint8Array(buf.slice(0, 16)));
  if (!kind) return json({ ok: false, error: 'Unsupported or invalid file. Please upload a real JPG, PNG, WebP, GIF or MP4.' }, 400);
  if (isImage && kind !== 'image') return json({ ok: false, error: 'That file is not a valid image.' }, 400);

  let ext = (type.split('/')[1] || 'jpg').toLowerCase().replace('jpeg', 'jpg').replace(/[^a-z0-9]/g, '').slice(0, 5);
  const key = 'p/' + Date.now().toString(36) + genToken().slice(0, 8) + '.' + ext;
  // Store a safe, sniffed content type so the bucket never echoes a hostile one.
  const safeType = (kind === 'image' && isImage) ? type : (kind === 'video' && isVideo) ? type : (kind === 'image' ? 'image/jpeg' : 'video/mp4');
  await env.IMAGES.put(key, buf, { httpMetadata: { contentType: safeType } });

  return json({ ok: true, url: '/img/' + key, key });
}

// Detect real media from the leading magic bytes. Returns 'image' | 'video' | null.
function sniffMedia(b) {
  const m = (arr, off = 0) => arr.every((v, i) => b[off + i] === v);
  if (m([0xFF, 0xD8, 0xFF])) return 'image';                                   // JPEG
  if (m([0x89, 0x50, 0x4E, 0x47])) return 'image';                             // PNG
  if (m([0x47, 0x49, 0x46, 0x38])) return 'image';                             // GIF
  if (m([0x42, 0x4D])) return 'image';                                         // BMP
  if (m([0x52, 0x49, 0x46, 0x46]) && m([0x57, 0x45, 0x42, 0x50], 8)) return 'image'; // WEBP (RIFF…WEBP)
  if (m([0x66, 0x74, 0x79, 0x70], 4)) return 'video';                          // MP4/MOV (…ftyp)
  if (m([0x1A, 0x45, 0xDF, 0xA3])) return 'video';                             // WebM/Matroska
  return null;
}
