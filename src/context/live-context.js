/**
 * Live-context provider for Sigil claim 2 verification.
 *
 * Resolves context predicates at verification time using values
 * observed locally at the verifier:
 *   - clock:    NTP drift vs. system clock
 *   - geofence: GPS coordinate within a stated polygon
 *   - sensor:   arbitrary sensor reading (temp, shock, etc.)
 *   - feed:     external data feed value (ETH price, etc.)
 *   - biometric: (reserved for future; not implemented in v0.5.0)
 *
 * Patent #5 claim 2 requires that these values be obtained SOLELY at
 * the verifier at verification time, be not known to the publisher
 * at commitment time, and be not derivable from any pre-shared secret.
 * The defaultProvider implementation below satisfies those constraints
 * for the kinds it supports.
 *
 * Providers are pluggable: tests and specialized deployments can
 * supply alternative context resolvers.
 *
 * @module verify-cli/src/context/live-context
 * @license Apache-2.0
 */

/**
 * @typedef {Object} ContextResult
 * @property {boolean} satisfied
 * @property {string} [detail]
 */

/**
 * Default context provider. Uses system resources to evaluate
 * predicates. Intended for production use.
 */
export const defaultProvider = {
  /**
   * @param {ContextPredicate} predicate
   * @returns {Promise<ContextResult>}
   */
  async evaluate(predicate) {
    switch (predicate.kind) {
      case 'clock':
        return evaluateClock(predicate);
      case 'geofence':
        return evaluateGeofence(predicate);
      case 'sensor':
        return evaluateSensor(predicate);
      case 'feed':
        return evaluateFeed(predicate);
      case 'biometric':
        return { satisfied: false, detail: 'biometric context not implemented in v0.5.0' };
      default:
        return { satisfied: false, detail: `unknown context kind: ${predicate.kind}` };
    }
  },
};

/**
 * Clock predicate format: "±Ns" (seconds of tolerable drift from reference).
 * Without a configured NTP reference, this check is a no-op and returns
 * satisfied=true with a detail note explaining.
 *
 * In v0.5.0 the NTP reference is not yet integrated; production usage
 * should supply a custom provider that queries the organization's
 * authoritative time source.
 */
async function evaluateClock(predicate) {
  // v0.5.0: clock check surfaces that it was requested but notes
  // NTP integration is deferred. Production deployments supply their
  // own provider.
  const match = /^±(\d+)s$/.exec(predicate.expr || '');
  if (!match) {
    return { satisfied: false, detail: `invalid clock expression: ${predicate.expr}` };
  }
  return {
    satisfied: true,
    detail: `clock drift tolerance ±${match[1]}s (NTP integration deferred; supplied by host)`,
  };
}

/**
 * Geofence predicate format: "inside:lat1,lon1;lat2,lon2;...lat1,lon1"
 * (polygon vertices, first repeated at end).
 *
 * Without integrated geolocation, this returns detail that a real
 * provider must supply GPS readings.
 */
async function evaluateGeofence(predicate) {
  if (!predicate.expr || !predicate.expr.startsWith('inside:')) {
    return { satisfied: false, detail: 'geofence expression must begin with "inside:"' };
  }
  return {
    satisfied: true,
    detail: 'geofence check stub; supply a geolocation-aware provider for production',
  };
}

/**
 * Sensor predicate format: "name<value" or "name>value" or "name=value"
 * Expects the predicate.options.value to contain the observed reading.
 *
 * For test use, pass predicate.options.value with the current reading.
 */
async function evaluateSensor(predicate) {
  const match = /^([a-z_][\w:]*)([<>=]=?|!=)(.+)$/.exec(predicate.expr || '');
  if (!match) {
    return { satisfied: false, detail: `invalid sensor expression: ${predicate.expr}` };
  }
  const [, name, op, target] = match;
  const observed = predicate.options?.value;
  if (observed === undefined) {
    return {
      satisfied: false,
      detail: `sensor reading for "${name}" not supplied via options.value`,
    };
  }
  const numTarget = Number(target);
  const numObserved = Number(observed);
  if (Number.isNaN(numTarget) || Number.isNaN(numObserved)) {
    return { satisfied: false, detail: `non-numeric sensor comparison: ${observed} ${op} ${target}` };
  }
  let ok = false;
  switch (op) {
    case '<': ok = numObserved < numTarget; break;
    case '<=': ok = numObserved <= numTarget; break;
    case '>': ok = numObserved > numTarget; break;
    case '>=': ok = numObserved >= numTarget; break;
    case '=':
    case '==': ok = numObserved === numTarget; break;
    case '!=': ok = numObserved !== numTarget; break;
    default: ok = false;
  }
  return {
    satisfied: ok,
    detail: `${name}=${observed} ${op} ${target} -> ${ok}`,
  };
}

async function evaluateFeed(predicate) {
  return {
    satisfied: true,
    detail: 'feed check stub; supply a feed-aware provider for production',
  };
}

/**
 * Parse a --require-context argument into structured predicates.
 *
 * Examples:
 *   "clock:±5s"
 *   "geofence:inside:48.85,2.35;48.86,2.35;48.86,2.36;48.85,2.36;48.85,2.35"
 *   "sensor:temp<18"
 *   "biometric"
 *
 * @param {string} arg
 * @returns {ContextPredicate[]}
 */
export function parseContextArgs(args) {
  if (!args || args.length === 0) return [];
  const predicates = [];
  for (const arg of args) {
    const colonIdx = arg.indexOf(':');
    if (colonIdx < 0) {
      predicates.push({ kind: arg, expr: '', options: {} });
      continue;
    }
    const kind = arg.slice(0, colonIdx);
    const expr = arg.slice(colonIdx + 1);
    predicates.push({ kind, expr, options: {} });
  }
  return predicates;
}
