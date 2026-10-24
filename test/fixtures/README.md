# Standalone regression fixtures

These files make the public checkout runnable without a sibling commercial or
monorepo checkout. Missing files are test errors, not skipped tests.

## Provenance and limits

| Corpus | Source and coverage | Limit |
| --- | --- | --- |
| `connector/connector-action.v1.json` | Byte-for-byte copy of the public protect-mcp producer's seven positive/negative connector-action vectors at commit `9579b6f47d4bfabf12511bd3859d449f3b04e5d0` | Producer/verifier compatibility for this corpus only, not independent authorship or operational evidence |
| `standalone/brass-v2.json` | Synthetic P-256 transcript, generated from the public transcript definition with fixed test-only scalars/nonces | Not a live issuer ceremony, formal proof or original monorepo producer integration |
| `standalone/governed-receipt-vectors.json` | Two pipe-delimited receipt payloads, two object-order vectors and one nested gate digest | Synthetic regressions for these wire examples, not a full canonicalization suite |
| `standalone/claims/` | Nine projection cases; 30 operator/finality cases; six module and ten decision cases; 21 evidence-admission cases; 12 strict-parser cases; one signed envelope with seven invalid variants | Explicitly synthetic regression corpus, not the unpublished normative Claims corpus or independent protocol validation |
| `standalone/test-vectors-v2.json` | Two synthetic envelopes signed by Node crypto using the public RFC 8032 test key; signature, digest, payload mutation and wrong-key checks | This file ships with `test/conformance.js` in the npm package; these keys establish no real issuer identity |

The connector file is from:

https://github.com/ScopeBlind/scopeblind-gateway/blob/9579b6f47d4bfabf12511bd3859d449f3b04e5d0/vectors/connector-action.v1.json

SHA-256: `444ce269142f05d530bd9337f3df98c1076717d85fd8f74dadc0573807dbeeca`.
Its MIT license and copyright notice are retained in `connector/LICENSE`.
The synthetic fixtures and their generator use this repository's Apache-2.0 license.
No private data or production keys are copied. The deterministic fixture keys and
nonces are intentionally unsuitable for production.

## Reproduction

```sh
npm ci
npm run check:fixtures
node --test test/unit/brass-v2.test.js test/unit/canonical-vectors.test.js test/unit/claims-v211.test.js test/unit/connector-action.test.js
npm run test:conformance
```

`check:fixtures` compares the committed synthetic files with independent fixture
construction. It never imports the verifier or its producer implementations and
never rewrites fixtures. Expected semantic verdicts are specified explicitly in
the generator. To deliberately regenerate after review:

```sh
node scripts/generate-standalone-fixtures.mjs
```

Changing the verifier and regenerating a matching expected answer is not a valid
regression fix. Explain why a changed expected answer follows from the specified
wire format and semantics. This corpus is not a complete or independently audited
specification.

## Additional producer corpora

The public suite always runs the checked-in files. Maintainers with other corpora
can additionally select explicit files/directories for a comparison run:

```sh
ACTA_CLAIMS_VECTORS_DIR=/absolute/path/to/specs/conformance/test-vectors node --test test/unit/claims-v211.test.js
ACTA_GOVERNED_VECTORS_FILE=/absolute/path/to/governed-receipt-vectors.json node --test test/unit/canonical-vectors.test.js
ACTA_CONNECTOR_VECTORS_FILE=/absolute/path/to/connector-action.v1.json node --test test/unit/connector-action.test.js
ACTA_ENVELOPE_VECTORS_FILE=/absolute/path/to/test-vectors-v2.json npm run test:conformance
```

An absent explicitly selected file fails. BRASS no longer imports an external
issuer implementation implicitly; a separate producer-integration run must be
reported as such. The existing legacy VOPRF, canonicalization, envelope, trust-pin
and integration suites remain separate tests.
