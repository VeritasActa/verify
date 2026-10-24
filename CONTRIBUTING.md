# Contributing to @veritasacta/verify

Help recipients check signed records with clear results and reproducible evidence.
You do not need a ScopeBlind account, signing key or commercial service to work on
the verifier. For sensitive reports, use [SECURITY.md](SECURITY.md) rather than a
public issue.

## Start from a clean checkout

Use Node.js 22 and npm. CI uses the exact versions recorded in
[verification.yml](.github/workflows/verification.yml); the package's runtime
minimum is recorded separately in [package.json](package.json).

```bash
git clone https://github.com/VeritasActa/verify.git
cd verify
npm ci
node cli.js samples/current-receipt.json --key ebb8cf3efc78717c50e7c438c0ad5498f8fa4e09607fea1e030ac129b5965225 --json
npm run check:fixtures
npm test
npm run test:conformance
npm run check:browser
npm run check:sigil
```

The sample key is public demonstration material, not an issuer identity to trust
for your own records. The sample should exit 0. With no `--key`, it should exit 2
(not checked); changing a signed payload field should exit 1 (failed). A wrong key
can also produce exit 1, so a failure alone does not establish tampering.

`npm ci` needs the network. The file-based receipt check runs offline after
installation. The tests use fixtures and local test servers; ordinary verifier
development does not require production credentials.

The standalone suite includes all fixtures it needs. Missing fixture files fail
instead of silently skipping coverage. The connector-action cases are pinned to a
public protect-mcp producer commit. BRASS, governed payloads and Claims v2.1.1 use
explicitly synthetic regression fixtures; they do not establish equivalence to the
unpublished producer corpus or independently assess the protocol. See
[test/fixtures/README.md](test/fixtures/README.md) for provenance, coverage and how
maintainers can additionally exercise an external producer corpus.

`check:fixtures` verifies deterministic regeneration without rewriting the committed
expected results. Review fixture changes separately from verifier changes. The
packed package also includes and runs its v2 envelope conformance vectors.

## Make a focused change

For a correctness or interoperability issue, provide a small synthetic fixture,
the exact command, expected outcome, actual exit status and relevant specification
section. Remove customer data and private keys. A passing fixture should normally
have a nearby negative case: for example, a changed signed field, wrong pinned key,
broken chain or unsupported input. State which checks your fixture exercises.

Useful first contributions include:

- Reproducing a receipt from another implementation with a positive and a negative
  fixture, including its independently supplied test key.
- Correcting a command that fails in an empty directory, with its expected output.
- Explaining an existing error or trust boundary with a small reproducible example.

For changes to trust rules, formats or exit behavior, open an issue first so the
maintainer can review compatibility. A successful signature check must not be
presented as proof of issuer authority, claim truth or complete action coverage.
Read [THREAT-MODEL.md](THREAT-MODEL.md) before changing these boundaries.

## Generated artifacts and package checks

Check generated files before regenerating them so an unexpected difference is
visible. When a reviewed change affects the browser engine, rebuild it:

```bash
npm run build:browser
npm run check:browser
```

After the final edit to a monitored file (including `README.md` or the browser
bundle), regenerate the integrity commitment using the existing public identity:

```bash
npm run generate-sigil
npm run check:sigil
npm run self-check
```

Do not use `--init`: it creates a new project key. Regenerating the commitment does
not require a private signing key and does not authenticate the publisher.

Then exercise the exact packed package in a temporary empty directory:

```bash
npm pack --json > packed.json
node scripts/release-install-check.mjs
```

That check installs the tarball and runs help, self-check, self-test and the public
receipt example, including negative cases. `packed.json` and the resulting `.tgz`
are local outputs, not files to commit.

The [TRACE comparison](docs/trace-fixtures.md) has a separate pinned-upstream CI
job. Its 11 fixtures and 35 compared checks do not cover policy freshness or session
binding. The [cross-project evidence page](https://github.com/ScopeBlind/agent-governance-testvectors/blob/main/docs/project-evidence.md)
distinguishes producer compatibility from independent-verifier coverage.

`npm run check:public` is for coordinated maintainers with sibling `Acta`, `.github`
and `drafts` checkouts. It is not required for a standalone contributor checkout.

## Pull requests and review

Explain the observable problem, the resulting behavior and the checks you ran.
Keep unrelated refactors out of correctness fixes. Disclose generated code where
it helps review; you remain responsible for understanding and testing the change.
No CLA is required. Contributions use this repository's existing Apache-2.0
license; preserve third-party notices. See [LICENSE](LICENSE), [PATENTS.md](PATENTS.md)
and [GOVERNANCE.md](GOVERNANCE.md) for the actual terms and decision process.

Only the maintainer runs the protected publishing workflow. Do not publish a new
package or change the version as part of an ordinary documentation or fixture PR.
