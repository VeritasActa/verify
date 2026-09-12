import assert from "node:assert/strict";
import test from "node:test";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// brass-voprf.js is a monorepo module (functions/fn/_lib). A standalone checkout
// of this package does not have it, so these tests skip there with a reason.
// The module resolves @noble from the repository root; when nothing is installed
// there, Node keeps walking up the directory tree and can land on an unrelated
// install outside the repository (a different major, different exports), which
// fails inside the import with a message that points nowhere useful. Resolve the
// dependency first and say plainly what was found.
const BRASS_LIB = resolve(fileURLToPath(new URL("../../../../functions/fn/_lib/brass-voprf.js", import.meta.url)));
const REPO_ROOT = resolve(dirname(BRASS_LIB), "../../..");
const brassDependencies = () => {
  if (!existsSync(BRASS_LIB)) return "needs fixtures from the monorepo root; not present in a standalone checkout";
  let found;
  try { found = createRequire(BRASS_LIB).resolve("@noble/curves/p256"); } catch (e) { return `@noble/curves is not installed for functions/fn/_lib (${e.code ?? e.message}); run npm ci at the repository root`; }
  if (!found.startsWith(REPO_ROOT)) return `@noble/curves for functions/fn/_lib resolves outside the repository (${found}); run npm ci at the repository root`;
  return false;
};
const SKIP = brassDependencies();
const MONOREPO = !SKIP;
const needsMonorepo = { skip: SKIP };
const brass = MONOREPO ? await import(pathToFileURL(BRASS_LIB).href) : {};
const { G, clientBlind, clientBuildRedemption, clientUnblind, encodePoint, issuerBlindEvaluate, issuerPublicKey, randScalar } = brass;
import { verifyVoprfToken } from "../../src/engines/voprf-token.js";

function ceremony() {
  const secret = randScalar();
  const issuerPublic = issuerPublicKey(secret);
  const scope = "opaque-scope-test";
  const kid = "brass-v2-test";
  const { r, M } = clientBlind(scope);
  const issued = issuerBlindEvaluate(secret, M);
  const Zprime = clientUnblind(r, issued.Z);
  const proof = clientBuildRedemption({
    scope,
    r,
    kid,
    issuerPkB64: issuerPublic,
    origin: "https://scopeblind.com",
    epoch: 1,
    policy: "legate-run-entitlement",
    window: 1,
    Mb64: M,
    Zb64: issued.Z,
    ZprimeB64: Zprime,
    cNonce: encodePoint(G.multiply(randScalar())),
    d: "run-digest",
    aadr: "run:test",
  });
  proof.type = "scopeblind.brass.redemption.v2";
  proof.piI = issued.piI;
  return { proof, issuerPublic, kid };
}

test("canonical BRASS v2 verifies only with the pinned issuer key", needsMonorepo, async () => {
  const { proof, issuerPublic, kid } = ceremony();
  const ok = await verifyVoprfToken(proof, { issuerPublicKey: issuerPublic, expectedKid: kid });
  assert.equal(ok.valid, true, ok.error);
  assert.equal(ok.dleq.issuer, true);
  assert.equal(ok.dleq.client, true);

  const unpinned = await verifyVoprfToken(proof);
  assert.equal(unpinned.valid, false);
  assert.equal(unpinned.error, "issuer_key_pin_required");
});

test("canonical BRASS v2 rejects transcript tampering", needsMonorepo, async () => {
  const { proof, issuerPublic, kid } = ceremony();
  proof.d = "different-run";
  const result = await verifyVoprfToken(proof, { issuerPublicKey: issuerPublic, expectedKid: kid });
  assert.equal(result.valid, false);
  assert.equal(result.error, "invalid_piC");
});
