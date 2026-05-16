/**
 * @veritasacta/verify — transparency profile engine.
 *
 * Implements the "one-click transparency switch": an operator config
 * that opts an agent into one of four standard disclosure tiers. The
 * engine exposes helpers to:
 *
 *   - Compute the transparency profile for a given config.
 *   - Stamp a receipt with its transparency-profile metadata.
 *   - Decide which receipts in a chain should be anchored publicly.
 *   - Render a publicly-consumable transparency badge JSON.
 *
 * Design is aligned with AIP-0005 (cost tiers) but orthogonal:
 * transparency is about what gets DISCLOSED, cost_tier is about what
 * it COST to mint. Both properties coexist on the same receipt.
 *
 * Profiles (caller-declared):
 *
 *   private      — receipts stay with operator (default; no change to existing behavior)
 *   auditable    — receipts kept privately but selective-disclosure proofs may be produced on demand
 *   transparent  — every receipt's hash is anchored in a public log; receipts queryable by URL
 *   high-assurance — transparent + compute-burn proof + multi-party + hardware attestation
 *
 * Picking a profile is a one-line declaration; the engine encodes the
 * implied behaviour.
 *
 * @module verify-cli/src/engines/transparency
 * @license Apache-2.0
 */

export const PROFILE_DEFINITIONS = {
  private: {
    id: 'private',
    label: 'Private',
    description: 'Receipts stay with operator; no public log anchoring.',
    // No additional obligations beyond the baseline receipt format.
    requires: [],
    optional: ['AIP-0002'],
    badge_color: '#6c757d',
  },
  auditable: {
    id: 'auditable',
    label: 'Auditable',
    description: 'Receipts kept private but verifiable via selective-disclosure proofs.',
    requires: ['AIP-0002'],
    optional: ['AIP-0003', 'AIP-0006'],
    badge_color: '#0b5394',
  },
  transparent: {
    id: 'transparent',
    label: 'Transparent',
    description: 'Every receipt hash anchored in a public log (Rekor/custom); receipts queryable by URL.',
    requires: ['AIP-0005-T4', 'public_anchor_endpoint'],
    optional: ['AIP-0002', 'AIP-0006'],
    badge_color: '#0a7c3f',
  },
  'high-assurance': {
    id: 'high-assurance',
    label: 'High assurance',
    description: 'Transparent + compute-burn proof + multi-party attestation + hardware backing.',
    requires: ['AIP-0005-T3', 'AIP-0005-T4', 'hardware_attestation'],
    optional: ['AIP-0007'],
    badge_color: '#b5271b',
  },
};

export const PROFILES = Object.keys(PROFILE_DEFINITIONS);

/**
 * @typedef {Object} TransparencyConfig
 * @property {keyof typeof PROFILE_DEFINITIONS} profile
 * @property {string} [anchor_endpoint]       e.g. "https://rekor.sigstore.dev"
 * @property {string} [public_receipt_base]   e.g. "https://audit.example.com/receipts/"
 * @property {string} [operator]              Shown on the badge.
 */

/**
 * Resolve a human config into a validated profile object.
 *
 * @param {TransparencyConfig} config
 * @returns {{ profile: string, definition: Object, warnings: string[] }}
 */
export function resolveProfile(config) {
  const profileId = (config && config.profile) || 'private';
  const definition = PROFILE_DEFINITIONS[profileId];
  const warnings = [];

  if (!definition) {
    return {
      profile: 'private',
      definition: PROFILE_DEFINITIONS.private,
      warnings: [`unknown_profile:${profileId}:falling_back_to_private`],
    };
  }

  // Soft requirement check: if profile claims "transparent" but no
  // anchor_endpoint is configured, we warn rather than downgrade —
  // the operator might be wiring it up.
  if (definition.id === 'transparent' && !config.anchor_endpoint) {
    warnings.push('transparent_profile_missing_anchor_endpoint');
  }
  if (definition.id === 'high-assurance') {
    if (!config.anchor_endpoint) {
      warnings.push('high_assurance_profile_missing_anchor_endpoint');
    }
  }

  return { profile: definition.id, definition, warnings };
}

/**
 * Stamp a receipt with its transparency profile metadata.
 *
 * The stamp goes under `payload.transparency`:
 *
 *   {
 *     transparency: {
 *       profile: "transparent",
 *       anchor_endpoint: "https://rekor.sigstore.dev",
 *       public_receipt_url: "https://audit.example.com/receipts/<hash>"
 *     }
 *   }
 *
 * This is DECLARATIVE only. It does not actually perform the anchoring
 * — that's the job of the anchor pipeline (see `rekor.js` for the
 * verifier side; the anchoring client is operator-run).
 *
 * Stamps the receipt in-place AND returns it for fluent composition.
 *
 * @param {Object} receipt
 * @param {TransparencyConfig} config
 */
export function stampTransparency(receipt, config) {
  if (!receipt || !receipt.payload) {
    throw new Error('stampTransparency: receipt must have a payload');
  }
  const resolved = resolveProfile(config);
  const payloadStamp = {
    profile: resolved.profile,
    ...(config.anchor_endpoint ? { anchor_endpoint: config.anchor_endpoint } : {}),
    ...(config.public_receipt_base
      ? { public_receipt_base: config.public_receipt_base }
      : {}),
  };
  receipt.payload.transparency = payloadStamp;
  return receipt;
}

/**
 * Decide whether a given receipt should be anchored publicly under
 * the supplied profile. Callers can iterate a chain and selectively
 * anchor only the qualifying receipts.
 *
 * Logic:
 *   - private:        never anchor
 *   - auditable:      never anchor (disclosure is on-demand)
 *   - transparent:    anchor every receipt
 *   - high-assurance: anchor every receipt AND require cost_tier >= 2
 */
export function shouldAnchorReceipt(receipt, profileId) {
  const p = receipt && receipt.payload;
  if (!p) return false;
  switch (profileId) {
    case 'private':
    case 'auditable':
      return false;
    case 'transparent':
      return true;
    case 'high-assurance':
      return Number(p.cost_tier ?? 0) >= 2;
    default:
      return false;
  }
}

/**
 * Render a publicly-consumable transparency badge JSON.
 *
 * This JSON is published by operators on their public transparency
 * page; consumers (regulators, auditors, end users) fetch it to
 * discover what profile the operator operates under.
 *
 * @param {TransparencyConfig} config
 * @param {{ receipts_anchored: number, last_anchored_at?: string }} [stats]
 */
export function renderBadge(config, stats = {}) {
  const resolved = resolveProfile(config);
  return {
    format: 'veritasacta:transparency-badge/v1',
    issued_at: new Date().toISOString(),
    operator: config.operator || '(unspecified)',
    profile: resolved.profile,
    label: resolved.definition.label,
    description: resolved.definition.description,
    requires: resolved.definition.requires,
    optional: resolved.definition.optional,
    badge_color: resolved.definition.badge_color,
    ...(config.anchor_endpoint ? { anchor_endpoint: config.anchor_endpoint } : {}),
    ...(config.public_receipt_base
      ? { public_receipt_base: config.public_receipt_base }
      : {}),
    stats: {
      receipts_anchored: stats.receipts_anchored || 0,
      last_anchored_at: stats.last_anchored_at || null,
    },
    warnings: resolved.warnings,
  };
}
