/**
 * registry.veritasacta.com — Cloudflare Worker
 *
 * Serves a public implementations registry for Veritas Acta ecosystem.
 * Each implementation signs a conformance claim with their own key and
 * registers via GitHub PR against the implementations/*.json file in the
 * agt-integration-profile repo. This worker is read-only: it mirrors the
 * canonical JSON files from the repo and serves them with appropriate
 * CORS and caching.
 *
 * Endpoints:
 *   GET /implementations.json
 *     Returns the full registry as a JSON array.
 *
 *   GET /implementations/{name}.json
 *     Returns a single implementation's record.
 *
 *   GET /implementations/{name}/attestation.json
 *     Returns the signed conformance attestation for the implementation.
 *
 *   GET /stats.json
 *     Returns aggregate stats (count, tier distribution).
 *
 *   GET /health
 *     Returns 200 OK.
 *
 * Authentication: none required for reads. Writes happen via GitHub PR.
 */

const REGISTRY_REPO = 'VeritasActa/agt-integration-profile';
const REGISTRY_PATH = 'implementations';
const CACHE_TTL = 300; // 5 minutes

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { pathname } = url;

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders() });
    }

    if (pathname === '/health') {
      return json({ status: 'ok', timestamp: new Date().toISOString() });
    }

    if (pathname === '/implementations.json') {
      const list = await fetchImplementationsList(env);
      return json(list);
    }

    if (pathname === '/stats.json') {
      const list = await fetchImplementationsList(env);
      return json({
        count: list.length,
        byTier: list.reduce((acc, impl) => {
          const tier = impl.claimed_tier || 1;
          acc[tier] = (acc[tier] || 0) + 1;
          return acc;
        }, {}),
        lastUpdated: new Date().toISOString(),
      });
    }

    const implMatch = pathname.match(/^\/implementations\/([a-z0-9-]+)(?:\/attestation)?\.json$/);
    if (implMatch) {
      const name = implMatch[1];
      const isAttestation = pathname.endsWith('/attestation.json');
      const impl = await fetchImplementation(env, name, isAttestation);
      if (!impl) return json({ error: 'not found', name }, 404);
      return json(impl);
    }

    return json({ error: 'not found', path: pathname }, 404);
  },
};

async function fetchImplementationsList(env) {
  const cached = await env.REGISTRY_CACHE?.get('implementations-list');
  if (cached) return JSON.parse(cached);

  const url = `https://api.github.com/repos/${REGISTRY_REPO}/contents/${REGISTRY_PATH}`;
  const res = await fetch(url, {
    headers: {
      'User-Agent': 'registry.veritasacta.com',
      Accept: 'application/vnd.github.v3+json',
    },
  });
  if (!res.ok) return [];

  const contents = await res.json();
  const impls = [];
  for (const file of contents) {
    if (!file.name.endsWith('.json') || file.name === 'attestation.json') continue;
    const data = await fetchImplementationJson(file.download_url);
    if (data) impls.push(data);
  }

  if (env.REGISTRY_CACHE) {
    await env.REGISTRY_CACHE.put('implementations-list', JSON.stringify(impls), { expirationTtl: CACHE_TTL });
  }
  return impls;
}

async function fetchImplementation(env, name, isAttestation) {
  const filename = isAttestation ? `${name}/attestation.json` : `${name}.json`;
  const url = `https://raw.githubusercontent.com/${REGISTRY_REPO}/main/${REGISTRY_PATH}/${filename}`;
  const res = await fetch(url, { headers: { 'User-Agent': 'registry.veritasacta.com' } });
  if (!res.ok) return null;
  return res.json();
}

async function fetchImplementationJson(downloadUrl) {
  try {
    const res = await fetch(downloadUrl);
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'content-type': 'application/json', ...corsHeaders() },
  });
}

function corsHeaders() {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, OPTIONS',
    'cache-control': `public, max-age=${CACHE_TTL}`,
  };
}
