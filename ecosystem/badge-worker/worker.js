/**
 * verify.veritasacta.com — Badge service (Cloudflare Worker)
 *
 * Returns shields.io-compatible badge SVG for Veritas Acta conformance
 * claims. Repositories embed these in their READMEs to advertise their
 * verifier version and tier.
 *
 * Endpoints:
 *   GET /badge/sigil/{fingerprint}.svg
 *     Returns a badge showing Sigil name + fingerprint for a given
 *     verifier release.
 *
 *   GET /badge/tier/{tier}.svg
 *     Returns a conformance-tier badge (T1-T5).
 *
 *   GET /badge/implementation/{name}.svg
 *     Returns a badge showing the implementation's registered tier
 *     (looked up from registry.veritasacta.com).
 *
 *   GET /badge/receipt.svg?kid={kid}
 *     Stateless "Verified by Veritas Acta" badge for a specific kid.
 */

const REGISTRY_URL = 'https://registry.veritasacta.com';

// Known Sigil names keyed by fingerprint. Extended over time as releases
// are published. The registry worker keeps the canonical list.
const KNOWN_SIGILS = {
  'dd0443f0': 'Slow Reed',
  'e6647ab1': 'Slow Cairn',
  '5247a989': 'New Wind',
  '87727f4b': 'Swift Wind',
  'cbefc999': 'Swift Wind',
  '6391ae72': 'Quiet Orchard',
  'b35f7301': 'Quiet Orchard',
  'd55af5f0': 'Lone Grove',
  '1a1e0f4e': 'Old Arrow',
  '7c6456ca': 'Lone Orchard',
  'f2f1d290': 'Dark Ember',
  'c52bc546': 'Bold Arrow',
  // Historical — extend as releases ship
};

const TIER_LABELS = {
  1: 'T1 basic',
  2: 'T2 disclosure',
  3: 'T3 attestation',
  4: 'T4 privacy',
  5: 'T5 full',
};

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const { pathname } = url;

    if (pathname === '/health') {
      return new Response('ok', { status: 200 });
    }

    const sigilMatch = pathname.match(/^\/badge\/sigil\/([0-9a-f]{8})\.svg$/);
    if (sigilMatch) {
      const fingerprint = sigilMatch[1];
      const name = KNOWN_SIGILS[fingerprint] || 'unknown';
      return svgBadge('Veritas Acta', `${name} · ${fingerprint}`, '#0d6e6e');
    }

    const tierMatch = pathname.match(/^\/badge\/tier\/([1-5])\.svg$/);
    if (tierMatch) {
      const tier = parseInt(tierMatch[1], 10);
      return svgBadge('Veritas Acta', TIER_LABELS[tier], tierColor(tier));
    }

    const implMatch = pathname.match(/^\/badge\/implementation\/([a-z0-9-]+)\.svg$/);
    if (implMatch) {
      const name = implMatch[1];
      const res = await fetch(`${REGISTRY_URL}/implementations/${name}.json`);
      if (!res.ok) return svgBadge('Veritas Acta', 'unknown', '#6b7280');
      const impl = await res.json();
      const tier = impl.claimed_tier || 1;
      return svgBadge('Veritas Acta', `${name} · ${TIER_LABELS[tier]}`, tierColor(tier));
    }

    if (pathname === '/badge/receipt.svg') {
      return svgBadge('Veritas Acta', 'Verified', '#059669');
    }

    return new Response('not found', { status: 404 });
  },
};

function tierColor(tier) {
  return ['#6b7280', '#059669', '#0d6e6e', '#2563eb', '#7c3aed', '#c026d3'][tier] || '#6b7280';
}

/**
 * Render a shields.io-compatible SVG badge.
 * Simple two-part badge: left label (gray), right value (colored).
 */
function svgBadge(label, value, color) {
  const labelWidth = 7 + label.length * 6;
  const valueWidth = 7 + value.length * 6;
  const totalWidth = labelWidth + valueWidth;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img" aria-label="${label}: ${value}">
  <title>${label}: ${value}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="${totalWidth}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="20" fill="#555"/>
    <rect x="${labelWidth}" width="${valueWidth}" height="20" fill="${color}"/>
    <rect width="${totalWidth}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="${(labelWidth * 10) / 2}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${(labelWidth - 10) * 10}">${label}</text>
    <text x="${(labelWidth * 10) / 2}" y="140" transform="scale(.1)" fill="#fff" textLength="${(labelWidth - 10) * 10}">${label}</text>
    <text aria-hidden="true" x="${(labelWidth + valueWidth / 2) * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${(valueWidth - 10) * 10}">${value}</text>
    <text x="${(labelWidth + valueWidth / 2) * 10}" y="140" transform="scale(.1)" fill="#fff" textLength="${(valueWidth - 10) * 10}">${value}</text>
  </g>
</svg>`;

  return new Response(svg, {
    headers: {
      'content-type': 'image/svg+xml',
      'cache-control': 'public, max-age=3600',
      'access-control-allow-origin': '*',
    },
  });
}
