// GET /api/track?courier=Delhivery&awb=XXXX
// Returns live shipment checkpoints (exact location + status) via AfterShip.
// DORMANT until AFTERSHIP_API_KEY is set in Cloudflare Pages settings — until
// then it returns {ok:false, reason:'not-configured'} and the site falls back
// to opening the courier's own tracking page.
import { json, rateLimit, clientIp } from './_shared.js';

// Our courier names -> AfterShip courier "slugs".
const SLUGS = {
  'Delhivery': 'delhivery',
  'Blue Dart': 'bluedart',
  'DTDC': 'dtdc',
  'India Post': 'india-post',
  'Xpressbees': 'xpressbees',
  'Ecom Express': 'ecom-express',
  'Ekart': 'ekart-logistics',
  'Shadowfax': 'shadowfax',
  'Amazon Shipping': 'amazon',
  'Professional Couriers': 'the-professional-couriers',
  'Trackon': 'trackon',
};

export async function onRequestGet(context) {
  const { request, env } = context;
  if (!env.AFTERSHIP_API_KEY) return json({ ok: false, reason: 'not-configured' });

  // Light abuse guard so a public endpoint can't burn the AfterShip quota.
  if (!(await rateLimit(env, 'track:' + clientIp(request), 40, 600))) {
    return json({ ok: false, reason: 'rate' }, 429);
  }

  const url = new URL(request.url);
  const courier = String(url.searchParams.get('courier') || '');
  const awb = String(url.searchParams.get('awb') || '').trim();
  if (!awb) return json({ ok: false, reason: 'no-awb' });
  const slug = SLUGS[courier];
  if (!slug) return json({ ok: false, reason: 'unsupported-courier' });

  const headers = { 'as-api-key': env.AFTERSHIP_API_KEY, 'content-type': 'application/json' };
  const base = 'https://api.aftership.com/v4/trackings';
  try {
    // Read the tracking first.
    let r = await fetch(base + '/' + slug + '/' + encodeURIComponent(awb), { headers });
    if (r.status === 404) {
      // Not registered yet — create it, then report "pending" (checkpoints
      // populate within a few seconds as AfterShip polls the courier).
      await fetch(base, { method: 'POST', headers, body: JSON.stringify({ tracking: { slug, tracking_number: awb } }) });
      return json({ ok: true, status: 'Pending', checkpoints: [], pending: true });
    }
    const d = await r.json();
    const t = d && d.data && d.data.tracking;
    if (!t) return json({ ok: false, reason: 'not-found' });
    const checkpoints = (t.checkpoints || []).map(function (c) {
      return {
        time: c.checkpoint_time || c.created_at || '',
        message: c.message || '',
        location: [c.city, c.state, c.country_name].filter(Boolean).join(', '),
        tag: c.tag || '',
      };
    });
    return json({
      ok: true,
      status: t.tag || '',
      subtag: t.subtag_message || '',
      expected: (t.expected_delivery || ''),
      checkpoints: checkpoints,
    });
  } catch (e) {
    return json({ ok: false, reason: 'error' });
  }
}
