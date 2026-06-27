// GET /img/<key> -> serve an image from the R2 bucket (public, cached)
export async function onRequestGet(context) {
  const { params, env } = context;
  if (!env.IMAGES) return new Response('Image storage not configured', { status: 500 });
  const key = Array.isArray(params.path) ? params.path.join('/') : String(params.path || '');
  if (!key) return new Response('Not found', { status: 404 });
  // Only ever serve uploaded media (the 'p/' prefix). Never expose other bucket keys.
  if (!key.startsWith('p/') || key.includes('..')) return new Response('Not found', { status: 404 });

  const obj = await env.IMAGES.get(key);
  if (!obj) return new Response('Not found', { status: 404 });

  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set('etag', obj.httpEtag);
  headers.set('cache-control', 'public, max-age=31536000, immutable');
  // Stop the browser from MIME-sniffing the bytes into something executable.
  headers.set('X-Content-Type-Options', 'nosniff');
  return new Response(obj.body, { headers });
}
