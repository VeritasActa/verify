## 0.11.0: Keys from outside the file for every format

### Upgrading from 0.10

- A Gate receipt tuple or evidence bundle, a macro snapshot or track record, a governed receipt, a proof or context pack, repository evidence, a standard file or a run manifest checked without `--key` exits 2 (undecidable), where 0.10 exited 0. Pin the signer's key with `--key` (or `--jwks`). `--allow-carried-key` keeps the earlier exit 0, and the output then says the signature was checked only against the key the file carries and proves nothing about who signed; `--strict` refuses it even then.
- A Knowledge Unit is never valid: it exits 1 when one of its receipts fails, and 2 otherwise, because its `receipt_sig` and `receipt_hash` are not checked (draft-farley-acta-knowledge-units-00 §8). A pipeline that waited for exit 0 on a KU must read exit 2 as not verified.

### Changes

- `--key` pins the ScopeBlind standard files and run manifests. A proof request and an admission decision must be signed with the recipient key given, a run manifest with the signer key given, and an action assurance bundle's gate request and receipt with the gate key given; a key that differs makes the file invalid (`key_mismatch`, exit 1), and the result reports the pin as `checks` entry `key_pin`. 0.10.28 checked each file against the key it carries and did not read `--key`, so a standard or a decision re-signed with a fresh key verified, exit 0, with the real recipient key pinned and `--strict`; and a bundle was valid under any `--key` and reported `signers_pinned: true`, which is now true only when the pins match. `--maintainer-key` is refused (exit 2) unless the file is a run manifest checked with `--standard`; elsewhere it was dropped. Earlier VALID results that change: each of these files under a `--key` that did not sign it is invalid.
- A VOPRF token is verified against the issuer key given with `--key`, never against the `issuer_public_key` it carries, and one that carries another key is invalid (`issuer_key_mismatch`, exit 1). 0.10.28 handed `--key` to the engine under a name it never read, and the engine fell back to the token's own key, so a token self-issued under a fresh key verified (exit 0, "T4 privacy") with no key, with another issuer's `--key`, and under `--strict`. With no key a token is undecidable (`missing_issuer_public_key`, exit 2). A BRASS 2.0 redemption (`protocol: "BRASS"`) is detected as a VOPRF token and verifies under its issuer's `--key`; 0.10.28 reported `unknown_format`, and with `--mode voprf` refused it for want of a key whatever `--key` said. `invalid_piI`, `invalid_piC` and `issuer_key_mismatch` are registered as invalid (exit 1, where 0.10.28 exited 2), and `missing_issuer_public_key` and `issuer_key_pin_required` as undecidable. Earlier VALID results that change: every token checked without `--key`, or under a key that did not issue it.
- A Knowledge Unit is never valid. It is invalid (exit 1) if one of the receipts it carries fails, and otherwise undecidable (exit 2): because it carries no receipts (`no_receipts`, new), because one cannot be checked, for want of a key or because it is in a format this verifier does not read (`unknown_format`), or because its `receipt_sig` and `receipt_hash` are present and not checked (`receipt_binding_not_checked`, new). They are not checked because draft-farley-acta-knowledge-units-00 §8 (Receipt Binding) does not define their preimage unambiguously: a KU has no member that says which receipts form each round, and round 2 records carry no slot; `receipt_hash` is bare hex in §3.6 and `sha256:`-prefixed in the §10 example; and §8 does not say whether `receipt_sig` signs the digest's bytes or its text. §11 (Receipt Replay) requires that chain to be recomputed before the content is relied on. 0.10.28 printed `Knowledge Unit: VALID, 0/0` (exit 0) for a KU with `receipt_sig: ""` and no receipts, skipped receipts it could not read and called the rest valid, called a KU valid whenever its receipts verified, and counted a receipt checked with no key as failed. The result names what was not checked, in `detail` and the new `notChecked` member. Earlier VALID results that change: every Knowledge Unit.
- A result that rests only on a key the file carries is undecidable (`embedded_key_rejected`, exit 2), by default and under `--strict`: a Gate receipt tuple or evidence bundle, a macro snapshot or track record, a governed receipt, a proof pack, a trusted context pack, repository evidence, a standard file or a run manifest checked without `--key` (or `--jwks`), and the detail says so. The new `--allow-carried-key` accepts such a result (exit 0), marks it `carriedKeyOnly: true`, and says, in the JSON `warning` and first in the terminal, that the signature was checked only against the key the file carries and proves nothing about who signed. `--strict` refuses it even with the flag. A run manifest whose harness key its standard accepts, under a maintainer key pinned with `--maintainer-key`, rests on that pin and is unaffected. 0.10.28 exited 0 for all of them, under `--strict` too, whose help said embedded keys are always rejected, so a Gate decision signed by any fresh key passed. Earlier VALID results that change: each of these files checked without a key is undecidable; pin the key with `--key`, or pass `--allow-carried-key` to keep the earlier result.
- `verify prompt` does not check the signature of the receipt or Sigstore bundle it is given, so a hash matched in one is undecidable (`signature_not_checked`, exit 2), and the output says the signature was not checked. 0.10.28 printed "prompt matches the asserted provenance" (exit 0) for an unsigned receipt, or a bundle with no signature, that named the hash. A hash that does not match still fails (exit 1), and `--expected-hash` is unchanged. Earlier VALID results that change: every `--prompt-receipt` and `--sigstore-bundle` match.
- `--fips` reads the algorithm the engine verified, after verifying, and Ed25519 is approved (FIPS 186-5 EdDSA). 0.10.28 read the file's unsigned top-level `algorithm` member before verifying and refused Ed25519, so an Ed25519 record labelled `ml-dsa-65` passed on its label and an Ed25519 receipt with its key pinned was refused. A format whose result names no verified algorithm (a Gate evidence bundle, a macro track record, a Knowledge Unit, a standard file or run manifest) is refused, as it was when unlabelled; a valid result carries `fips: { algorithms, approved }`. A BRASS 2.0 result reports the algorithm it verified (`voprf-p256-sha256`), not the token's label. Earlier VALID results that change: a file that passed `--fips` on a label alone is refused (exit 2).
- `verify daemon` hashes the RFC 8785 canonical form of the full arguments, as `verify proxy` does, and records `tool_input_hash_method: jcs-sha256-v1`. 0.10.28 passed the top-level member names to `JSON.stringify` as a replacer, which keeps only those names at every depth, so `{"query":{"sql":"DROP TABLE users"}}`, `{"query":{}}` and `{"query":{"sql":"SELECT 1"}}` all hashed to the same value, and one receipt covered a harmless call and a destructive one. Receipts the daemon signed before carry no `tool_input_hash_method`; their hash does not bind nested arguments.
- Every JSON file a verification reads is read as the main input is, with a member name given twice refused: each line of `--replay-chain`, both files of `--diff`, the files beside a run manifest (`--standard`, `--receipts`, `--calls`, `--regrade`, `--provenance`, `--model-attestation`, a `--maintainer-key` file), a `--jwks` key set (file or URL), the receipts `chain explore` and `compliance` read, a `verify prompt` receipt or bundle, and a `--known-issuers` map. 0.10.28 read them with `JSON.parse`, which keeps the last of two members, so a receipt with `"decision":"deny"` before `"decision":"allow"`, refused as the main input (exit 2), verified on `--replay-chain` (exit 0). Such a line is now undecidable (`malformed_json`); a key set is `jwks_fetch_failed`; a file beside a manifest or given to `--diff` stops the run (exit 2); `chain explore` and `compliance` skip the file as malformed, and a label map is ignored.
- A receipt's `cosignatures` and its `authorization.delegation_chain` are reported as not checked, in the new `notChecked` member and under "Not checked" in the terminal, wherever the receipt is verified: alone, in an audit bundle (whose terminal summary counts them) and on `--replay-chain` (in the warnings). The CLI has never checked either: `src/engines/cosign.js` and `src/engines/delegation.js` are library functions it does not call, though the 0.5.3 entry below says the verifier walks delegation chains. 0.10.28 verified a receipt with a junk cosignature and a dangling delegation chain (exit 0) and mentioned neither. The outcome is unchanged: they are reported, not counted.
- Removed dead code: `normalizeNumbers` in `src/util/canonical.js`, whose condition (not an integer, and an integer) could never hold and which nothing called, and `cli-v0.4.0.js.bak`, a stale copy of the CLI kept in the repository (it was never in the package). The browser bundle is rebuilt; its behaviour is unchanged.
- `--audit-log` chains each entry to the one before it, as the log's own description says: `_chain_hash` is the SHA-256 of the previous entry's `_chain_hash` followed by the entry. 0.10.28 never passed the previous hash, so every entry was hashed as if it were the first, and entries could be removed or reordered without breaking any hash. An entry is not appended to a log whose last line carries no chain hash; the verification is unaffected and a warning says why. Entries written before keep their hashes, each computed as if it were the first; the first entry written after this release chains to the last of them.
- Library only (the CLI does not call it): `src/engines/rekor.js` hashes a receipt as the SHA-256 of the RFC 8785 form of the whole receipt, and `verifyRekorAnchor` requires a signed tree head, verified against the key pinned for its log in `logTrustAnchors` and naming the proof's tree size and root (`signed_tree_head_missing`, `no_log_trust_anchor`, `signed_tree_head_mismatch`). 0.10.28 passed the member names to `JSON.stringify` as a replacer, so every `{payload, signature}` receipt hashed to the same value, and returned valid for a one-leaf proof anyone can make, with no signed tree head.

## 0.10.28: Complete license, contribution guides and checked installation example

- Include the complete Apache License 2.0 text in the published package, preserving the existing copyright notice and license. This does not relicense the project.
- Add contribution and governance guides, focused issue/PR templates, and accurate support and release-integrity documentation. Git tags are not described as signed; npm provenance and the bundled integrity commitment are separate mechanisms.
- Replace obsolete roadmap promises and monorepo paths in the ecosystem overview with explicit maintained, experimental and historical status. Nested ecosystem READMEs link to that status before their legacy setup instructions.
- Extend the existing clean-install release gate to exercise the public receipt example from the packed package: valid with the documented demonstration key, not checked with no key, and failed with a wrong key or changed signed payload. Verification behavior and the pinned TRACE results are unchanged.
- Update the lockfile's transitive `fast-uri` from 3.1.7 to 3.1.9, within AJV's existing version constraint, resolving npm advisory GHSA-hrr3-gc8f-f4qj. No dependency API or verifier logic changes.
- Refresh release metadata and the bundled integrity commitment for these source changes. The browser engine bytes are unchanged; its build manifest carries the new package version.

## 0.10.27: Keys from outside the file, the signed issued_at, and disclosures that are read

Found while checking 0.10.26 against the -04 editor's copy (VeritasActa/drafts). Each fix below names the earlier VALID results it changes.

- An audit bundle's own keys are no longer a trust anchor. The keys in `verification.signing_keys` arrive in the file being verified, so anyone who can write a bundle can name a key there for any receipts. 0.10.26 checked the receipts with them whenever no `--key` was given, printed `Bundle: VALID` (exit 0) for a bundle that carried the key that signed it, and labelled each receipt `keySource: provided`. Without `--key` or `--jwks` the receipts are now undecidable (`no_public_key`, exit 2), and the result says why. `--trust-bundle-keys` checks them with the bundle's keys, as before, reports `keySource: bundle` on the bundle and on each receipt, and warns that a valid result shows only that the receipts match keys carried in the same file. `--key` takes precedence over `--jwks`, and either over `--trust-bundle-keys`. `--strict` disables the flag, and it is refused (exit 2) for a file that is not an audit bundle, and with `--replay-chain`, `--diff`, a subcommand, `--self-check` or `--self-test`. Earlier VALID results that change: a bundle checked with its own keys and no `--key` or `--jwks` is undecidable.
- `--jwks` gives each receipt in an audit bundle the key its own `kid` names. 0.10.26 gave every receipt the key set's first Ed25519 key, whatever its `kid`, so a bundle holding receipts from two issuers failed every receipt the first key did not sign (`invalid_signature`), and a receipt whose `kid` the set lacks was checked with a key it never named. The key set is read once, as for `--replay-chain`; a receipt whose `kid` it lacks is undecidable (`jwks_fetch_failed`, naming the `kid`), with no fall back to the bundle's own keys; a set that cannot be read checks nothing (exit 2). The window of the key the set gives is applied to each receipt's signed `issued_at`, and each receipt reports `keyStatus`. Earlier VALID results that change: a receipt whose `kid` the set lacks is undecidable; one issued outside its key's window is invalid (`key_outside_validity_window`); one whose window cannot be applied is undecidable.
- A bundle's outcome combines its receipts' as §5.3 of the -04 editor's copy combines checks: invalid (exit 1) if any receipt is invalid, else undecidable (exit 2) if any receipt could not be checked, else valid. 0.10.26 exited 2 for every bundle that did not verify, one with a tampered receipt included, though the terminal said `INVALID`. The result carries `outcome`, `error` (the code of the first receipt with that outcome), `keySource` and `undecidable`, and `failed` counts invalid receipts only.
- The key validity window reads only the `issued_at` the signature covers: the payload's in the envelope shape, the top-level one in the flat shapes, and only as an RFC 3339 date-time string. 0.10.26 fell back to an `issued_at` or `timestamp` beside an envelope's payload, which the signature does not cover, then to a `timestamp` in the payload, and read a number as epoch seconds or milliseconds. Any of those now leaves the window undecidable (`key_window_unverifiable`, exit 2), with a detail that says the signed bytes carry no `issued_at` or names the value. `keyStatus.issued_at` reports the signed value as written. Without a window nothing changes. Earlier VALID results that change, under a key source that gives a window: an envelope whose payload has no `issued_at` but which carries one, or a `timestamp`, beside the payload; a receipt whose only time is a `timestamp`; and a receipt with a numeric `issued_at`. All three are undecidable. One earlier INVALID result changes too: protect-mcp's commitment-mode receipts carry a `timestamp` and no `issued_at` in their payload, so 0.10.26 placed them in a window by that time and could fail them with `key_outside_validity_window`; under a window they are undecidable now.
- `--disclosure-file` is checked against the `committed_fields_root` the signature covers: in an envelope's payload, where draft §2.2 puts it, or at the top level of a flat receipt (or in a v2 receipt's payload). 0.10.26 looked at the top level only, so an envelope's root was never found and the file given with it was not read: an envelope whose payload root no disclosure in the file matches was valid, exit 0. It is `commitment_mismatch` (exit 1) now. A root beside an envelope's payload is outside the signature and is no longer used; 0.10.26 checked disclosures against it.
- `--disclose` (AIP-0002) is checked against the `_commitments` map the signature covers, read the same way: an envelope's payload, or the top level of a flat receipt. 0.10.26 read the top level of every receipt, so an envelope's disclosures were checked against a map beside the payload that nobody signed, and the terminal listed that map's fields as committed. A map beside an envelope's payload is no longer read, and a failure already found is no longer replaced by `commitment_mismatch`. Earlier VALID results that change: a `--disclose` checked against an unsigned map is undecidable (below).
- A disclosure that cannot be applied is undecidable, with the new code `disclosure_not_applied` (exit 2), and the detail says why: a `--disclosure-file` that cannot be read, is not JSON, holds no disclosure, or meets a receipt whose signed bytes carry no `committed_fields_root`; or a `--disclose` value that is not `field:salt:value`, or one given for a receipt whose signed bytes carry no `_commitments` map. 0.10.26 ignored such a disclosure (exit 0) or, for an unreadable file beside a top-level root, reported the unregistered code `disclosure_file_load_failed: <message>`, which also replaced a failure already found. A failure already found now stays the outcome. Both flags are refused (exit 2), not dropped, where they do not apply: an audit bundle or any other file that is not one receipt, `--replay-chain`, `--diff`, a subcommand, `--self-check` and `--self-test`. Earlier VALID results that change: a receipt given a disclosure that cannot be applied is undecidable, and one whose disclosures do not match the root in its payload is invalid.
- A proof's leaf count is read as `tree_size`, the name draft §6.5 gives it (as -02 and -03 did), and `treeSize`, the only name 0.10.26 read and the one protect-mcp writes, is still accepted for compatibility. A disclosure whose proof was written to §6.5 failed with `commitment_mismatch`; it is checked now. A proof that gives both names with different values, or a count that is not a whole number, does not verify. An earlier INVALID result changes: a correct proof that spells it `tree_size` verifies.
- A key carried in the signed bytes must be the key the receipt is verified with. A carried key is the value of a `public_key`, `verification_key` or `verification_jwk` member of the signed bytes: the payload of an envelope, or the receipt, and a v2 receipt's payload, in the flat shapes. When the key comes from `--key`, from `--jwks`, or from a bundle trusted with `--trust-bundle-keys`, a carried key that is not that key makes the receipt invalid, as §5.3 of the -04 editor's copy has it: `key_mismatch` (exit 1), the code the Gate, governed-receipt and proof-pack checks already give a carried key that is not the one pinned with `--key`. 0.10.26 looked for carried keys only when no key was given, so a receipt signed by the anchored key while carrying another key's `public_key` was valid under both `--key` and `--jwks`. Keys are compared as 32 bytes: 64 hex characters in either case, base64 or base64url, or an OKP Ed25519 JWK; a value in none of those forms is not the anchored key. A receipt that carries the anchored key itself, as protect-mcp's receipts do, is unaffected, and so is one checked with no key, whose carried key is still refused as `embedded_key_rejected` (exit 2). The check runs beside the others and is reported as `checks.carried_key`; under a key that did not sign the receipt the code reported is still `invalid_signature`. `--replay-chain`, bundles and the browser bundle apply it too. Earlier VALID results that change: a receipt that carries a key other than the one it is verified with is invalid.
- An envelope's `issuer_id` must match its signature's `kid`, as §2.2 says (`issuer_id` "MUST match the kid field in the signature object"). When the payload names an `issuer_id` that is not `signature.kid`, or names one while the signature object has no `kid`, the receipt is invalid, with the new code `issuer_kid_mismatch` (exit 1). 0.10.26 never compared the two. A payload with no `issuer_id` is not checked: the gap is reported in `payloadNotes` and the outcome does not change. The check reads the bytes alone, so, like a malformed chain link, it counts with or without a key, and is reported as `checks.issuer_kid`; under a key that did not sign the receipt the code reported is still `invalid_signature`. The flat shapes are not checked, as their rules are still being settled with implementers. `--replay-chain`, bundles and the browser bundle apply it too. None of the receipts in ScopeBlind/agent-governance-testvectors, TRACE's Acta fixtures or the receipts protect-mcp writes names an `issuer_id` other than its `kid`. Earlier VALID results that change: an envelope whose `issuer_id` is not its `kid`, or which names an `issuer_id` and no `kid`, is invalid; checked with no key, where 0.10.26 reported it undecidable (`no_public_key`), it is invalid too.
- A key from `--jwks` is reported as `keySource: jwks`, where 0.10.26 reported `provided`, and the terminal's trust line says the key came from the issuer's published key set.
- Payload notes. For an envelope, the new `payloadNotes` member names what the payload lacks against §2.2 of the -04 editor's copy (a `type`, `issued_at` or `issuer_id`, or a signature object with no `kid` when no `issuer_id` names one) and against its declared type (§3.1.1 and §3.2.1: a `protectmcp:decision` with no `tool_name`, or a `decision` outside `allow`, `deny`, `rate_limit` and `require_approval`, say). The terminal lists them under "Payload notes". They do not change the outcome or the exit status: such receipts are valid, as in 0.10.26, and now say what they lack. Making a missing member change the outcome was held back, because receipts that verify today would turn invalid: protect-mcp's commitment-mode receipts have no `issued_at` or `issuer_id` in their payload, and the x-agent-trust attestations in ScopeBlind/agent-governance-testvectors (`a2a-trust-header/`) have no `type` or `issuer_id`. The flat shapes get no notes.
- ERRORS.md and the registry: `issuer_kid_mismatch` and `disclosure_not_applied` are new; `malformed_encoding`, which earlier releases emitted with no entry (a signature or key that is not hexadecimal, or a signed object that cannot be canonicalized, such as one with a member name that is not ASCII), is registered as undecidable, so a bundle that fails with it reads `NOT CHECKED`, not `INVALID`, and the JSON carries its `errorMeta`; `key_mismatch` covers a carried key in an Acta receipt; `no_public_key` says a bundle's own keys are not a trust anchor and names `--trust-bundle-keys`; `key_window_unverifiable` names the signed `issued_at`; `jwks_fetch_failed` covers a bundle; and the `unsupported_algorithm` hint no longer says ML-DSA needs "v0.6+": ML-DSA-65, alone or in a hybrid, is not implemented, so a receipt that declares it is undecidable (`unsupported_algorithm`), as it was. The same stale claim leaves `docs/reference.md` and THREAT-MODEL.md.
- The browser bundle carries the receipt engine and the error registry, so it is rebuilt. A receipt checked there gets the carried-key and issuer checks and the payload notes; the browser has no bundles, disclosures or key windows. The module headers it keeps as license comments, which are this project's own text (`src/detect.js`, `src/util/canonical.js`), no longer carry em dashes; the third-party notices it keeps are unchanged. The README, ROADMAP and reference describe the commercial applications neutrally.
- JSON changes, all in results this release touches: `checks.carried_key` when a key from outside the receipt is used and the signed bytes carry one; `checks.issuer_kid` when an envelope's payload names an `issuer_id`; `payloadNotes` on envelopes that lack something; `keySource: jwks` for a key from `--jwks`; on a bundle, `outcome`, `error`, `keySource` (`provided`, `jwks`, `bundle` or `null`), `undecidable`, a `detail` when no key was given and a `warning` with `--trust-bundle-keys`, with `failed` counting invalid receipts only, and `keyStatus` on each receipt checked with `--jwks`; `keyStatus.issued_at` as written in the signed bytes, so a number stays a number; `committedFieldsRoot` and `redactedFields` from the signed bytes only; and `errorMeta` for `malformed_encoding`.
- The bundle change above applies to Acta audit bundles alone. Gate receipt tuples and evidence bundles, macro track records, governed receipts, adherence and restraint proof packs, and trusted context packs still verify against the key they carry when no `--key` is given, and exit 0 when it verifies. Such a result shows only that the record matches the key it carries, not who holds that key; give the expected key with `--key` to pin it. Their results say so: `keySource` is `embedded-tuple` for Gate receipt tuples and trusted context packs, `embedded-receipt` for governed receipts and `embedded-pack` for proof packs, with `(pinned via --key)` added when a key is given; `identityStatus` is `embedded_key_only` for Gate receipt tuples and macro track records, which a macro track record reports without a `keySource`. The terminal says so too: "Trust tier: key embedded in the artifact (pin it against a source you trust before relying on it)" for Gate receipt tuples, trusted context packs, governed receipts and proof packs, and "Identity: embedded key only" for a macro track record. A Gate evidence bundle carries no such label in its JSON, and its terminal lists the signing keys it saw and the role each signed.
- Not changed here: the flat shapes' rules; the legacy AIP-0002 commitment format itself; and every other exit status. The run-manifest check with `--receipts` reads the receipt log with the website's verifier, bundled as `src/engines/legate-core.mjs`, which this release leaves as it is: it checks each receipt with the manifest's gateway key and does not yet compare that key with a key the receipt carries, compare an `issuer_id` with its `kid`, or refuse a signature member in the signing input. It changes with the web verifier in a later release. No Internet-Draft is revised or resubmitted by this release.

## 0.10.26: A receipt and the one before it, and three outcomes on every path

- `--previous <receipt.json>` checks one receipt against the receipt the caller says it follows. Its `previousReceiptHash` must be the §6.7 link of that receipt: `sha256:` and the lowercase hex SHA-256 of the JCS of the whole receipt, or the bare hex of earlier revisions. An absent, `null` or different link is a `chain_break` (exit 1) whose detail says which. Supplying the predecessor asserts the succession, so a receipt that names none does not follow it, as §6.7.1 of the -04 editor's copy (VeritasActa/drafts) has it; `--replay-chain`, which asserts no order, still reads such a receipt as the start of a new chain. A payload-only link is refused unless `--allow-payload-only-links` is given, and `--strict` disables that flag. One run checks the signature, the key window and the link, with `--key` or `--jwks`. The JSON result carries `previous`: the expected link, the link as written, its form and the result. A link it matched is a verified `chain-linkage` feature rather than a declared one. The flag is refused (exit 2), not dropped, with `--replay-chain`, `--bundle`, `--diff`, a subcommand, a file that is not one Ed25519 receipt, or a predecessor that cannot be read or is not a JSON object. TRACE's fixture 09 verified alone on 0.10.25; checked after fixture 07 with `--previous` it is a `chain_break`.
- `--replay-chain` takes keys from `--jwks`. It ignored the flag and failed every line with `no_public_key`. The key set, a URL or a file, is read once; each receipt's key is the one its `kid` names, and that key's validity window is applied to its `issued_at`, as for a single file. A `kid` the set does not have makes that line undecidable (`jwks_fetch_failed`, naming the `kid`), and a set that cannot be read stops the replay before anything is verified (exit 2). `--key` takes precedence. `--require-key-window`, which replay also ignored, applies to it now.
- Three outcomes, as §5.3 of the -04 editor's copy (VeritasActa/drafts) has them: a verification that makes several checks is invalid if any check ran and failed, even when another could not run; undecidable if none failed and at least one could not run; valid only when every check that applies passed. Every check that can run on a receipt now runs: the signing input, the signature, the link's syntax, the key window and, with `--previous`, the link to the receipt supplied. 0.10.25 applied the key window only once the signature and the link's syntax held, so a validly signed receipt whose link names another hash algorithm and whose `issued_at` is outside its key's window was undecidable (exit 2); it is invalid (exit 1, `key_outside_validity_window`). A receipt with a malformed link is invalid (`malformed_chain_link`) even when no key can check its signature, where 0.10.25 reported `no_public_key` or `jwks_fetch_failed`. The code reported is the first failure in a fixed order, so a tampered receipt still reports `invalid_signature`, or the first check that could not run when none failed. The JSON result carries `outcome` and `checks`, each check's result and code; `outcome` also counts the checks made after a receipt's own (a selective disclosure, a live-context predicate, `--tier`), whose exit statuses are as before. The connector-action profile is still checked only once the receipt's own checks pass.
- The terminal headline names the outcome and the check that decided it: `INVALID: chain link does not follow the previous receipt (chain_break)`, or `INVALID: key outside its validity window (key_outside_validity_window)`, on a single receipt and with `--previous`; on `--replay-chain` it names the first line with that outcome, as `INVALID: line 2: ...`. It read `Signature: INVALID` for every failure, so a receipt whose signature held and whose link or key window failed was reported as an invalid signature. A `Signature:` line under the headline says what the signature check itself found: valid, invalid, or not checked and why. A result that is not a receipt keeps its old headline.
- `--replay-chain` exits 1 if any line is invalid or any link breaks, else 2 if any line could not be checked, else 0. It exited only 0 or 1, so a file none of whose receipts could be checked, for want of a key, exited 1 as if each had failed. A link naming another hash algorithm is undecided, not a `chain_break`, and a line that is not JSON is undecidable. The summary carries `outcome` and `undecidable`, and the terminal names the outcome and the exit status. `verified`, `failed` and `undecidable` count lines, each once, by outcome: `failed` counted a line once for its link and again for its signature, and counted lines that could not be checked. Each line carries `outcome`, `checks` and `keyStatus`.
- Key windows read only RFC 3339 date-times that write their UTC offset out (`Z` or `±hh:mm`). They compared times with `Date.parse`, which reads a time with no offset in the machine's own time zone: `issued_at` `2026-05-31T23:30:00` against a window ending `2026-06-01T00:00:00Z` was inside it under `TZ=UTC` and outside it under `TZ=America/New_York`. Such a time, a date alone, prose, a day that does not exist (30 February) or a bound written as `null` now makes the window undecidable (`key_window_unverifiable`, exit 2), and the detail names the value and the cause. A bound the key set leaves out still leaves the window open on that side, and `keyStatus.window` now leaves it out too, where it wrote `null`.
- A key given with `--key` has no source for a window, so its validity at issuance is not established: `keyStatus.result` is `not_established` (it was `not_applicable`), and the terminal says so in one line. That is not a failure, and the exit status does not change. When no key is resolved at all it is `not_run`.
- `--allow-payload-only-links` is labelled as what it is. §6.7.1 of the -04 editor's copy (VeritasActa/drafts) says a verifier must not accept a payload-only link, so reading one is a compatibility mode for chains the proxy and daemon of 0.9.3 and earlier wrote, not conformance. Wherever one is read (`--replay-chain`, `chain explore`, `--previous`), the JSON carries `conformant: false`, and the terminal summary, the warnings and the `--audit-report` page say it was read under a compatibility mode, not conformant to draft §6.7. `--help` and `docs/reference.md` say the same. The exit status does not change.
- The run-manifest check with `--receipts` reads the receipt log with the website's verifier, bundled as `src/engines/legate-core.mjs`, which 0.10.25 left for this release. It now refuses a link over the previous receipt's payload alone whatever that receipt cites, reads a link's hex in lowercase only, by the expressions of `checkChainLinkSyntax`, reports a link naming another hash algorithm as leaving the chain undecided rather than broken (`chain_outcome` in the result, and the terminal line), and no longer reads a `previousReceiptHash` from beside an envelope's signed payload. The core is regenerated from the web source, so it also takes the repository-evidence changes the site has had since 16 September: approvals valid for up to seven days, signed revocations of approvals, evidence links on success criteria, and the workflow run that produced a coding result. 0.10.25 refused evidence carrying those members.
- `--self-check` covers `src/engines/legate-core.mjs`, the website's verifier core bundled here for the run-manifest, standard and repository-evidence checks. It was not among the Sigil's monitored files, so a changed core still passed the self-check. The monitored list, and so the source hash, change with it, and the release test that every shipped module is monitored counts `.mjs` modules as well as `.js`. A core synced from the web source now needs the Sigil regenerated, as any monitored file does.
- No string users see carries an em dash: the error registry (the `context_requirement_unmet` spec reads `Patent #5 claim 2: Live-context verification`, as ERRORS.md did), `--help`, the self-check and self-test headings, the terminal and HTML reports and their placeholders, the compliance report, the governed-receipt lines, the `.gitignore` entry `init` writes, the replay errors and the watch alerts.
- `scripts/trace-fixtures.mjs` runs TRACE's Acta fixtures (agentrust-io/trace-spec, `examples/action-receipts/acta`) through `cli.js`, compares each column this CLI decides with `expected.json`, and writes `docs/trace-fixtures.md`; `.github/workflows/trace-fixtures.yml` fails when the page differs from a run at the pinned trace-spec commit. At 0e2457d7, the head of agentrust-io/trace-spec#592: 11 fixtures, 35 checks compared, no differences. `policy_freshness` and `session_binding` are not compared, since the CLI takes no policy or session context.
- The browser bundle carries the receipt engine and the error registry, so it is rebuilt. A receipt checked there gets the same combination of its signing input, signature and link; the browser has no key windows, `--previous` or replay.
- JSON changes, all in results this release touches. Every receipt result carries `outcome` and `checks`; `--previous` adds `previous`; a link read under `--allow-payload-only-links` adds `conformant: false`, in replay, `chain explore` and `--previous` results alike. `keyStatus.result` is `not_established` for a key given with `--key`, where it was `not_applicable`, and `not_run` when no key was resolved; `keyStatus.window` leaves out a bound the key set leaves out, where it wrote `null`. A receipt whose `kid` the JWKS does not have is reported with its own fields and checks, so its `format` is the receipt's (`passport`, say), where it was the detected mode. `--replay-chain` adds `outcome`, `undecidable` and, when a legacy link was read, `conformant`; `verified`, `failed` and `undecidable` count lines once each, by outcome; each entry in `receipts` carries `outcome`, `checks` and `keyStatus`, and a line that is not JSON is listed there too, with `error: malformed_json`, where it was left out. The run-manifest `chain` carries `chain_outcome`.
- Not changed here: the link syntax 0.10.22 set and the payload-only refusal of 0.10.25; replay's reading of a receipt with no link as a new chain; `chain explore`'s exit statuses; the exit status with `--allow-payload-only-links`; the connector-action, selective-disclosure and live-context checks. Exit statuses for connector-action failures are still 2, as their codes are not in the error registry. No Internet-Draft is revised or resubmitted by this release.

## 0.10.25: Replay and chain explore refuse payload-only chain links

- `--replay-chain` and `verify chain explore` now refuse a `previousReceiptHash` computed over the previous receipt's payload alone, with `chain_break` (exit 1), whatever that receipt's `spec` says. Draft-farley-acta-signed-receipts-03 §6.7 defines the link as the SHA-256 of the JCS of the whole previous receipt, signature included, and -02 §5.7 defined the same preimage. -01 defines no link, and no revision defines one over the payload: hashing the payload alone gives a re-signed receipt the same link as the original, which is what §6.7 rules out. Replay since 0.10.0, and explore since 0.10.23, accepted such a link after a receipt citing -01 or -02 or carrying no `spec` member, and `spec` is optional, so a -03 receipt without one could be followed by a payload-only link and replay as valid. The payload-only case in TRACE's Acta fixtures (agentrust-io/trace-spec#592: `09-payload-only-chain-link.json` after `07-valid-inside-key-window.json`) replayed and walked as valid on 0.10.24, and is now a `chain_break` on both paths. The refusal says the link hashes the payload alone and names the flag below.
- `--allow-payload-only-links` reads such a link as a legacy link instead, whatever the previous receipt cites. Each one is counted (`legacyLinks` in replay, `legacy_links` in explore) and named in the warnings, in the terminal, in JSON and in the `--audit-report` page. It applies to that preimage only: a link over the whole receipt is read as before, and any other mismatch is still a `chain_break`. Among this project's published tools, only `verify proxy` and `verify daemon` in 0.9.3 and earlier wrote payload-only links, and they stamped every receipt `spec: draft-farley-acta-signed-receipts-03`, so 0.10.0 to 0.10.24 already refused their chains. The flag is how to read one of those chains now. `--strict` disables it.
- `--strict` now applies to `--replay-chain` and `chain explore` as well as to a single file. It was applied only after replay had run, so `--replay-chain` with `--allow-legacy-canonicalization --strict` still accepted a historical non-JCS signature, and with `--allow-embedded-key --strict` still used an embedded key, though `--strict` is documented to disable both.
- `--replay-chain` reports each chain a file holds. A receipt after the first with no `previousReceiptHash`, or with `null` as 0.9.3 wrote on a first receipt, starts a new chain: draft §2.2 says such a receipt is a chain genesis or an unchained receipt, and that a verifier must not infer chain membership from the absence. Replay passed it without a word, so "Chain breaks: 0" read as one unbroken chain. It is still not a break, since a `receipts.jsonl` the proxy appended to over several sessions holds one chain per session, but the result now counts `chains` and names each new start in `warnings`, beside the receipt verifier's own warnings (a `null` link, a historical encoding), which replay used to drop.
- A `previousReceiptHash` that is not a string no longer stops `--replay-chain` with "Fatal error: expectedPrev.startsWith is not a function" (exit 2). It is a `chain_break` and, from the receipt verifier, `malformed_chain_link` (exit 1).
- `--trust-anchor <file>` is refused (exit 2) before anything is verified. From 0.5.1 it was parsed, listed in `--help` and named as a key source in error hints, but never read: a plain receipt was refused for want of a key (`no_public_key`), while an audit bundle, a Gate bundle or, with `--allow-embedded-key`, an embedded key verified against the keys the input carried, exit 0, with the anchor ignored. Pin the key with `--key`, or with `--jwks` and a URL or a local JWKS file. The `no_public_key` and `embedded_key_rejected` hints no longer name it.
- Error specs cite sections the published -03 has. `invalid_signature` in ERRORS.md cited §6.1, which is Merkle Tree Construction; it now cites §6.6 Signature Scope, as `errors.js` did. `chain_break` in ERRORS.md cited "§5.4 Chain Linkage", which -03 does not have; it now cites §6.7 Chain Hash Scope, as `errors.js` did. `embedded_key_rejected` cited "Security Considerations: Key Distribution" and now cites §9.5 Key Distribution and Trust Anchors. `dleq_verification_failed` cited a "VOPRF Token Verification" section the draft does not have and now cites RFC 9497. The README cites no sections.
- `--jwks` reads a Windows drive-letter path such as `C:\keys\acta-keys.json` as a file. It parsed as a URL with the scheme `c:` and was refused as "Unsupported JWKS URL scheme: c:". A single letter and a colon at the start of the argument are now read as a drive letter, since no URL scheme in use is one letter long.
- The browser bundle carries the error registry, so it is rebuilt. Built without minification, it differs from 0.10.24's only in the registry's strings this release changes (the `chain_break`, `no_public_key` and `embedded_key_rejected` hints, the `embedded_key_rejected` and `dleq_verification_failed` specs) and one source comment; minified, some identifier names shift with them. No browser verification code changed.
- Not changed here: the run-manifest check in the bundled core (`src/engines/legate-core.mjs`, synced from the web verifier) has the same payload-only fallback, and reads a link's hex without regard to case. It changes with the web verifier in the next release.

## 0.10.24: Shared browser verification and public release contract

- Browser bundle built from the CLI detector, canonicalizer and Ed25519 receipt engine.
- Current protect-mcp envelope parity, external-key-only browser checks, and explicit unsupported outcomes.
- Versioned historical website receipt verification, without elevating unsigned key metadata or claiming draft-03 conformance.
- Duplicate-member JSON rejection and bounded input parsing in browser and CLI.
- Shared release/status manifest; verification-first docs; corrected self-check and failure semantics.
- Regression coverage for wrong/missing keys, mutation, legacy receipts, malformed input and bundle parity.

No automatic trust installation, changes to patent terms, or Internet-Draft resubmission.

## 0.10.23: Chain explore reads section 6.7 links

- `verify chain explore` now follows draft-farley-acta-signed-receipts-03 §6.7 chains. It looked ancestors up by an unprefixed base64url SHA-256 of each receipt, a form no revision of the draft defines, so it never found the ancestor named by a `sha256:` link and reported every conformant chain as broken at its first link. It now indexes each receipt by the hex SHA-256 of the JCS of the whole receipt, signature included, and reads each link by the rules the receipt verifier applies since 0.10.22. A link in the bare 64-character form of earlier revisions resolves too, and so does a payload-only link from an ancestor that cites -02 or earlier, as `--replay-chain` allows.
- A link refused for its form stops the walk with the receipt verifier's code: `malformed_chain_link` (exit 1) or `unsupported_chain_hash_algorithm` (exit 2). The result's new `code` field carries it. An unprefixed base64url link is now refused as malformed, as `verify` refuses it on a single receipt.
- Each node's `hash` is now its §6.7 value, the one a successor's link holds, and each node reports `link_form`: `sha256`, `legacy-bare-hex` or `legacy-payload`. The result counts `legacy_links`. A `null` link still ends the walk at a root, with a warning citing §2.2.
- On VeritasActa/e6-fixture `v1.0.1`, explore walks all 51 receipts of the billing period from `0086.json` and reports the oldest one's link, which names a receipt from the previous period, as not found. 0.10.22 stopped at the first link.
- The audit dashboard in `ecosystem/dashboard`, which is not part of the npm package, had the same lookup and showed every link of a §6.7 chain as a break. It now computes the same value, and on pasted `chain explore --json` output it keeps the hashes explore reported.

## 0.10.22: Chain link syntax

- Refuse a receipt whose `previousReceiptHash` is malformed with `malformed_chain_link` (exit 1), and one whose prefix names an algorithm other than sha256 with `unsupported_chain_hash_algorithm` (exit 2), once its signature holds and whether or not the predecessor is supplied. Draft-farley-acta-signed-receipts-03 §6.7 requires the link to be `sha256:` followed by 64 lowercase hex characters, and requires refusing a prefix that names an algorithm the verifier does not implement. Until this release a single receipt's link was not read, so a correctly signed receipt carrying `sha256:not-a-digest`, a `sha512:` link, uppercase hex or a string that is not a digest was reported valid. A chain check already refused a link that does not name its predecessor.
- The bare 64-character digest of earlier revisions is still accepted on read, as §6.7 allows. A `null` link, which the 0.9.3 proxy and daemon wrote on a chain's first receipt, still verifies, with a warning citing §2.2. Each receipt result reports the link form it accepted in `chainLink`: `sha256`, `legacy-bare-hex` or `null`.
- 0.10.22 still passes all 25 members of `vectors-receipt-signature` in probityai/agent-evidence-vectors 0.17.4, with and without the key windows, and verifies all 51 receipts of VeritasActa/e6-fixture `v1.0.0`.

## 0.10.21: No signature member in the signing input

- Refuse an envelope receipt whose payload carries a `signature` member, including `null` and the empty string, with `signature_in_signing_input` (exit 1), even when a signature over those bytes verifies. Draft-farley-acta-signed-receipts-03 §6.6 requires that the object canonicalized for the signature never contain one. Until this release the envelope path verified `JCS(payload)` without checking, so such a receipt was reported valid. Flat receipts are unaffected: their own signature member is removed before canonicalizing, as §6.6 describes.
- Found by @astrogilda with `vectors-receipt-signature` in probityai/agent-evidence-vectors 0.13.0 (member `v5397adb77c3e6754`). 0.10.21 passes all 13 members in both passes, with and without the key windows.

## 0.10.20: Key validity windows

- Apply the signing key's `valid_from` / `valid_until` window from the JWKS to a receipt's `issued_at` (draft-farley-acta-signed-receipts-03 §9.2). The window is `[valid_from, valid_until)`: a receipt issued exactly at `valid_until` is outside it, as RFC 7519 treats `exp`. A receipt issued outside the window fails with `key_outside_validity_window` (exit 1). Until this release the receipt path ignored the window; the claims path already applied its own.
- Report the key status for every receipt, in `keyStatus` (JSON) and in the terminal: `inside`, `outside`, `no_window` (the key source carried no window, so the key's validity at issuance is not established, never reported as valid), `unverifiable` (unreadable bounds or no readable `issued_at`: `key_window_unverifiable`, exit 2), or `not_applicable` (a key pinned with `--key`).
- `--require-key-window` fails a receipt whose key source gives the key no window (`key_window_missing`, exit 2).
- Found by @giskard09 and @robertolocatelli81-dev with the `farley-receipt-signature` vectors in argentum-core. 0.10.20 matches all four at `541ce84` on their strict verdicts.
- Refuse a verification key carried at the top level of the v2 and flat shapes the same way as one carried inside the payload (`embedded_key_rejected`, draft §9.5). The v2 path looked only inside `payload`, so a top-level `public_key` fell through to `no_public_key`: still refused, but without naming the cause. Found by @arian-gogani's embedded-key vectors (ScopeBlind/agent-governance-testvectors#24), which 0.10.20 passes 4/4.

## 0.10.19: Connector actions

- Check the `connector` member of a decision receipt (draft-farley-acta-connector-action-00): schema, the consistency of the recorded check with the presented signature, and, given `--platform-key <kid>=<hex>`, the platform's signature over the context itself. A receipt whose recorded context is not what the platform signed is `connector_context_signature_invalid`; a malformed member is `connector_schema_invalid`; a signature the verifier holds no key for is reported unverifiable and is never a failure by itself.
- Report the platform, agent, grant, recorded check, signature result and effect in the terminal and JSON output. Receipts without the member are unchanged.

## 0.10.18: Coding work and project devices

- Recognize `scopeblind.repository.coding-evidence.v1`: check separate dual authority, exact recorded feedback, bounded work, publication admission and worker-attested PR/preview result.
- Verify fresh review origins from coding work and project-scoped device statements, including the service's recorded authority check. Old valid history remains verifiable after device revocation.
- Keep publication, merge approval, recipient acceptance and independent key pinning distinct in the report. Verification does not execute the build, fetch preview bytes or establish code correctness.

## 0.10.17 (2026-09-16)

- Verify signed repository review briefs, exact proposal-bound preview observations, and the matching packet decision for every ordinary approval or rejection. Historical repository evidence stays supported.
- Verify scoped agent findings and feedback against dual-signed preparation authority and service-recorded use; verify a fresh review’s registered origin against the exact frozen source feedback. Preparation never substitutes for human merge approval.
- Distinguish mutable external preview links, provider observations, artifact digests when present, and recipient acceptance. No preview code is executed during verification.

## 0.10.16 (2026-09-16)

- Verify repository collaboration evidence offline: exact visual model hashes, Git blob identities, scoped agent suggestions and signed feedback linking fresh tasks.
- Keep approval, observed destination effect, rendered preview and recipient acceptance distinct. Existing repository v1 evidence remains supported.

## 0.10.15 (2026-09-16)

- Derive assurance features from successful verification, with unchecked declarations reported separately. Metadata alone never raises a conformance tier.
- Bind proxy receipts to all nested forwarded tool arguments using JCS and SHA-256; mark the hash method explicitly.
- Serialize numeric-looking and prototype-named JSON keys correctly. Verify exact signed payload fields and reject historical non-JCS signatures by default; `--allow-legacy-canonicalization` is an explicit, labeled compatibility option.
- Add portable repository-task evidence verification using the same implementation as the browser, including exact dual approval and receiver-reported outcome boundaries.

# Changelog

## 0.10.14 (2026-09-14)

- The package's integrity commitment (`sigil.json`) is regenerated for this release. 0.10.13 shipped carrying the 0.10.12 commitment, so `--self-check` on 0.10.13 reports it stale; nothing else differs from 0.10.13. The release gate now catches this before a site deploy, which is how it was found.

## 0.10.13 (2026-09-13)

- A result the verifier could not decide is reported as `NOT CHECKED (<code>)`, not `INVALID`. No key it may trust (`no_public_key`, or `embedded_key_rejected` when the only key is inside the signed bytes), an unknown shape (`unknown_format`), a missing signature, and the other undecidable codes all exit 2 and say which; `INVALID` and exit 1 are reserved for a check that ran and failed. A script that needs the distinction reads `error` from `--json`, as ERRORS.md says. Prompted by the embedded-key review on ScopeBlind/agent-governance-testvectors#21, where the two could not be told apart from the exit status alone.

## 0.10.12 (2026-09-13)

- A grading by a grader the standard does not name is reported as a third word the standard did not choose: it is shown, agreeing or disagreeing, and it never binds, so no one can manufacture a contradiction by supplying an artifact. A named grader's disagreement still blocks.
- Gradings carry how the tests were run: the profile (black box, where the tests never import the submission; in process, where they do and the submission's code ran inside the scoring interpreter), the hygiene check for scoring-hijack configuration, and whether pytest's summary, its JUnit report, and its exit status agreed. The regrade's environment declares who administers it, what implementation ran the tests, where the tests came from, and what the judgment is.

## 0.10.11 (2026-09-12)

- Exit status means what a CI gate needs it to mean. A run manifest given companion files exits 1 unless it binds to all of them; alone it still exits 0 and says unbound. Before this, a mutated receipt log could fail a check, report `binding: partial`, and exit 0 (found by aeoess).
- The receipt log and the calls log are checked as bytes: `receipts.jsonl` and `calls.jsonl` as given must hash to the digests the manifest records, not merely parse to the same records (found by aeoess).
- The gate policy digest is recomputed from the policy text the standard carries, instead of two declared digests being compared (found by aeoess).
- `--maintainer-key <hex|file>` pins the maintainer key that must have signed the standard, a trust root from outside the files; the report then establishes who signed the standard instead of asking you to pin it.

## 0.10.10 (2026-09-12)

- Readable names. Certificate subjects and issuers print as `CN=..., O=...` instead of raw attribute OIDs, in the Sigstore and Intel TDX chains alike.
- The mode line names the artifact: a run manifest reads `Legate verified run (run manifest), checked offline`, a standard, a decision, and an action bundle each their own, instead of one line listing all four.
- What a run establishes reads in the order a reader asks: the signed account, the standard, the receipts, the gradings, the provenance, the model route, then the keys; each line shorter, repositories and workflows by name.

## 0.10.9 (2026-09-12)

- `--regrade` is repeatable. The first is the run's own second grading; each further one is a grading made elsewhere (`regrade_2`, `regrade_3`, ...), verified the same way: under its grader key, for this manifest, accepted by the standard (a listed key, or the provenance identity of a bundle given with `--provenance` that names the grading's exact bytes), distinct from the harness key, and agreeing with every verdict and workspace. One accepted, agreeing grading reconciles the verdicts; every grading supplied must hold for the run to bind. The first such grader is VeritasActa/verified-runs-grader.
- A second grading is accepted by the key the standard names, or by the provenance identity the standard names (`trust.accepted_grader_provenance`) when the regrade's own bytes carry a verified bundle from that identity: a grader elsewhere needs no key listed in advance. The report says which repository made the regrade and whether it is the run's own or another.
- Keys by provenance. When a run's manifest and receipts carry verified provenance and its gateway and harness keys are not the demonstration keys, the verifier reports them as generated inside the attested workflow run; otherwise it says which keys are demonstration keys, and always says the maintainer key must be pinned through a channel of the reader's own.

## 0.10.8 (2026-09-12)

- A run manifest's `model_calls` pin (the digest and count of the signed model-calls log) is part of the signed body. 0.10.7 computed the manifest digest without it and refused every attested manifest as altered; this release verifies them. A manifest without the field is unchanged.
- Attestation reports from a gateway (`model_attestations[]`, one per model node) are expanded to their entries.

## 0.10.7 (2026-09-12)

- Attested model route. `--model-calls model-calls.jsonl` and `--model-attestation model-attestation.json` verify, offline, that every model call of a run was signed inside the inference provider's TEE (NEAR AI Cloud's shape: a secp256k1 signature over `{model}:{sha256(request)}:{sha256(response)}`), that each signing key is bound in an attestation report whose Intel TDX quote chains to the pinned Intel SGX Root CA (quote signature, quoting-enclave binding and signature, PCK chain, validity), and that the attested model is the one the standard names. The report's GPU evidence and the platform's TCB status are carried and named, not verified here. Adds `verifyTdxQuote` to the engine.

## 0.10.6 (2026-09-12)

- `--provenance`: a bundle made in another run verifies on its own terms but does not count for this manifest, and unbinds nothing; it contradicts the manifest only when it names the manifest's own bytes. A deterministic standard is attested by every run that used it, so `gh attestation download standard.json` returns every run's bundle, and a reader may well hold bundles from other runs.

## 0.10.5 (2026-09-12)

- `--provenance <path>` for Legate run manifests: the Sigstore provenance bundles beside a run (`provenance/*.sigstore.jsonl`, a file or a directory, repeatable) are verified here, offline, against the pinned Sigstore public-good trust root: the certificate chain to Fulcio, the workflow identity in the certificate (issuer, workflow, repository, commit, run) against what the manifest names, the DSSE signature, the Rekor entry (log key, entry body, signed entry timestamp, integration time inside the certificate's validity), the inclusion proof and signed checkpoint, and the certificate-transparency SCT. Each file given on the command line must be a subject of a verified bundle, by its exact bytes. `gh attestation verify` remains an independent path.
- Run manifests may name the commit and the workflow the run was made at (`environment.attestation.commit`, `.workflow`); when present, the certificate must agree.

## 0.10.4 (2026-09-11)

### Added
- Run manifests bind two more things. `--calls <file>` takes the calls log (one call per receipt: tool and input) and checks that every receipt's input digest opens to the call recorded, so an allowed shell receipt is no longer a digest a reader cannot look behind. `--regrade <file>` takes a second grading (`scopeblind.run_regrade.v1`): the pinned tests re-run on the archived workspace, signed under a grader key the standard accepts and distinct from the harness key; the verifier reconciles it with the manifest, and a standard that asks for independent reconciliation is held until a second grading agrees. Manifests may pin each attempt's workspace and the calls log by digest. These answer the first outside review of a verified run (arian-gogani, nobulex): the verdicts were the harness's word, and an input digest could not tell a listing from an egress.

## 0.10.3 (2026-09-11)

### Added
- Consumed authority. An effect readback may carry a signed `authorization` block: the destination consumed the gate's receipt as a single-use authorization for exactly these terms before it committed (kind, receipt digest, request id, consumed at, spend index). A standard that sets `requirements.receiver_consumes_authorization` is evaluated with a `consumption` check: a readback without a cited authorization is held, not accepted. Readbacks made before the block existed verify byte for byte; a readback that carries the block needs this version or later, because the block is under the signature.
- `requirements.credentials_held_by_gate`: the credentials the gateway holds and injects. The gateway receipt report checks that every allowed call to the tool records the label (`credential_ref`), never the value.

## 0.10.2 (2026-09-11)

### Changed
- Run manifests: the harness key that signed the manifest must be one the standard accepts as a readback source (`trust.accepted_readback_sources`), checked as `harness_key`. Without it a manifest re-signed under a fresh key verified as intact with nothing tying it to the maintainer. Manifests made before this cut fail the check against their standards until the standard names the harness key, which is the point.

## 0.10.1 (2026-09-11)

### Added
- Run manifests (`scopeblind.run_manifest.v1`): a harness's signed account of a governed run, such as a benchmark submission made with every tool call through the gateway. Alone, the file verifies as intact and prints its result. With `--standard <standard.json>` and `--receipts <receipts.jsonl>` beside it, the verifier checks that the manifest names that standard by digest, that the receipts are the ones the manifest names (count and chain head), that every receipt cites the policy compiled from the standard, that every allowed call names a tool on the standard's list, that no task exceeds the allowed attempts or time, that the task-set and harness pins match, and that the gateway key is one the standard accepts. What it does not establish is printed with it: who holds the keys, whether the sandbox enforced its network rule (that is the environment attestation's job), and anything the agent said.

## 0.10.0 (2026-09-11)

### Added
- Legate standard files verify with the one command: a signed standard (`scopeblind.proof_request.v1`), a recipient decision (`scopeblind.admission_decision.v1`), and an action assurance bundle (`scopeblind.action_assurance_bundle.v1`) are detected and verified by the same core the Legate site runs, bundled as `src/engines/legate-core.mjs` and synced from the web package. Force it with `--mode legate`. A green result names what it does not establish: who holds the key, and for a bundle without `--key`, that any signer is pinned.

### Changed
- `chain replay` accepts the pre-03 payload-only link only when the predecessor cites draft -02 or earlier, or no spec. Under -03 a payload-only link is a chain break, because accepting it would let a re-signed receipt keep the original's link, which is what section 6.7 closes. Legacy links taken are counted in `legacyLinks`.

## 0.9.7 (2026-09-10)

### Documentation says what exists

No code change. The README advertised an SDK that is not on npm or PyPI,
seven adapter packages that were never published, two hostnames that do not
resolve, Sigstore provenance the releases do not carry, and a Homebrew install
path that is not the tap. It now names the four published packages
(protect-mcp, protect-mcp-adk, @scopeblind/langchain, scopeblind-swarms),
points at the source adapters and SDK helpers as source, says which ecosystem
workers are deployed (none), and describes the supply chain as it is.

ROADMAP is rewritten from this changelog: shipped since 0.5.4, what is next,
and the two deprecated flags that are still parsed. SECURITY's supported
versions start at 0.9.x. THREAT-MODEL pins this release. No em dashes remain
in the shipped documentation.

The README is part of the monitored verifier surface, so the bundled
integrity commitment (`sigil.json`) is regenerated and this release has a new
Sigil name. `--self-check` on 0.9.6 and on 0.9.7 each match their own bytes.

## 0.9.6 (2026-09-10)

### Fix: extra positionals are an error, not a silent drop

`verify a.json b.json` verified only `b.json` and exited on that, printing
one verdict for the whole set. The parser assigned every positional to the
same `opts.file`, so the last one won and the rest were discarded without a
word. A conformance suite that handed the verifier a glob was therefore
checking one receipt in four (reported as finding 7 in
ScopeBlind/agent-governance-testvectors#13).

Every subcommand takes at most one file; `--diff` carries a second one as a
flag. So a second positional is never legitimate, and it now exits 2 with a
message naming every file given. Nothing is verified in that case. A verifier
that silently discards inputs is not correct, it is quiet.

Chain-link fixes from 0.9.5 are unchanged.

## 0.9.5 (2026-08-31)

### Fix: 0.9.4 shipped with a stale Sigil commitment

0.9.4 carried the correct chain-hash code but the `sigil.json` commitment from
0.9.3. Every install of 0.9.4 therefore failed its own integrity check:

    npx @veritasacta/verify --self-check
    x Monitored verifier source does not match the bundled commitment
      It may be a fork, a development build, or a tampered copy.

The source was never wrong. `src/engines/{proxy,daemon,bulk}.js` and
`src/errors.js` are all in MONITORED_FILES, so editing them for the 0.9.4 fix
invalidated the commitment, and `generate-sigil.mjs` was not re-run before
publishing. This release regenerates it.

`--self-check` and `--self-test` both pass on 0.9.5. Verified against a real
install rather than the source tree.

Use 0.9.5, not 0.9.4. The chain-hash fix below is present and correct in both;
only 0.9.4's integrity commitment is wrong.

## 0.9.4 (2026-08-30)

### Fix: the chain link was computed over the wrong bytes

`proxy` and `daemon` emitted `previousReceiptHash` as `"sha256:"` followed by
the hash of the receipt's **payload**. The settled rule
(draft-farley-acta-signed-receipts-03 section 6.7) is the hash of the **entire
signed receipt including its signature member**. Both engines now do that.

This was invisible because the read path in `bulk` accepts either form, so
chains this tool wrote verified against this tool and would have failed any
verifier implementing 6.7 strictly. Reported by an outside reviewer building
an independent verifier.

Hashing the payload alone gives a re-signed receipt the same chain link as the
original, so a key rotation or re-issue is invisible in the chain. Verified:
two receipts with identical payloads signed by different keys now produce
different links, and the emitted links match what protect-mcp independently
computes for the same receipt.

### Fix: genesis receipts carried `previousReceiptHash: null`

Section 2.2 requires the first receipt in a chain to omit the member entirely
rather than carry `null`, because the two produce different JCS output and
therefore different signed bytes. Both engines now omit it.

### Spec citations corrected

Error metadata and chain comments cited section 5.4 and draft-02 section 5.7,
both superseded numbering. They now cite 6.6 (Signature Scope) and 6.7 (Chain
Hash Scope). The stale citations are why the rule appeared to be missing from
a release that partly implemented it.

### Upgrading

Chains written by 0.9.3 or earlier still verify: the read path accepts the
payload-only form for chains predating the rule. Chains written by 0.9.4
will not verify against 0.9.3 or earlier.

## 0.9.3 (2026-07-08)

### Tree reconciliation: the 0.9.1/0.9.2 line and this line are one again

npm 0.9.1/0.9.2 were published from a tree that had diverged from this one.
This release unifies them: everything published there now lives here
(restraint-receipt openable detail with re-hashed bindings and the
`Prevented:` terminal block, `verifyRestraintBindings` export, the RFC 9711
EAT output modes `--emit-eat` / `--emit-eat-cbor`, the `verify` bin alias,
`samples/sample-restraint-receipt.json`), and everything that had only
lived here ships to npm for the first time (Legate proof-pack, macro
snapshot and track-record, and trusted-context-pack engines).

### draft-02 receipts and s5.7 chain links

protect-mcp 0.10.0 emits draft-farley-acta-signed-receipts-02 envelopes;
these verified here already via the passport path. `--replay-chain` now
recomputes chain links under both conventions: the draft-02 section 5.7
hash (SHA-256 over the JCS bytes of the entire previous envelope, signature
included) and the older payload-only hash, so a mixed pre/post-migration
receipt log replays cleanly including the link that spans the boundary.

### s5.7 chain links in --replay-chain

`--replay-chain` now recomputes chain links under both conventions: the
draft-farley-acta-signed-receipts-02 section 5.7 hash (SHA-256 over the JCS
bytes of the entire previous envelope, signature included), which is what
protect-mcp 0.10.0+ writes, and the older payload-only hash for chains
written before the migration. A mixed pre/post-migration receipt log
replays cleanly, including the link that spans the boundary.

Tree reconciliation blocker: RESOLVED in this release (see above).


## 0.9.0 (2026-06-22)

### Legate adherence / restraint proof packs

Recognizes and verifies `scopeblind.legate.proof-pack.v1`: the allocator-facing,
position-blind record a Legate desk produces of what the gate prevented over a
session (held / blocked, attributed to the committed-mandate rules) plus order-path
shadow evidence (what it would have blocked on a FIX feed), bound to the mandate
digest, the signed book provenance, and a receipt Merkle root. The signature is
Ed25519 over the canonical (deep-sorted, no-whitespace) bytes of the pack minus its
`signature`, `sha256`, and `hybrid_signature` fields, against the embedded runtime
`verification_key` (pin it with `--key`). Cross-implementation tested against a real
desktop-runtime-signed fixture (`samples/legate-proof-pack.json`); tampering with any
field, and a wrong pinned key, fail. An optional `hybrid_signature` (Ed25519 +
ML-DSA-65) is recognized and reported; classical Ed25519 is verified here, with PQ
verification documented as an optional add-on in the restraint-receipts draft.

## 0.8.0 (2026-06-13)

### RFC 6962 transparency log for macro track records

Recognizes `scopeblind.macro.transparency-head/1` and
`scopeblind.macro.transparency-witness/1`, and verifies the `transparency`
evidence carried in a macro track-record bundle: every record's Merkle
inclusion proof against the signed head (RFC 6962 hashing: leaf =
sha256(0x00||digest), node = sha256(0x01||l||r)), plus an independent witness
co-signature. The bundle result reports `Transparency: witness-anchored /
self-signed / not anchored`; a tampered head or a missing inclusion fails the
chain check. No new signing crypto: inclusion is recomputed from the path and
checked against the head root. This is what makes a dropped or rewritten record
detectable to anyone who retained a head, not merely a single un-trimmed export.

### ScopeBlind macro-engine snapshots and track-record bundles

New engine `src/engines/macro-snapshot.js` recognizes the macro-engine
schemas (`scopeblind.macro.market-state/1`, `regime-snapshot/1`,
`tape-snapshot/1`, `vulnerability/1`, `alert/1`, `journal-entry/1`) and the
signed track-record bundle (`scopeblind.macro.track-record-bundle/1`). Macro
snapshots already verified cryptographically as generic Gate tuples; this adds
schema recognition, a per-schema semantic-contract check, and a schema-aware
summary in the output (no more "unrecognized schema" for macro records). No
new cryptography: crypto is delegated to `verifyGateTuple` and canonicalization
to `canonicalGateJSON`.

The track-record bundle verifier mirrors the Gate evidence-bundle: it checks
every record's signature, single-signer custody (every record including the
manifest shares one model key), exact manifest completeness (entries enumerate
the snapshots then journal entries in order), the snapshot/journal counts, and
the `history_head_digest` over the ordered record digests. Dropping or
tampering any record breaks the bundle. `--mode macro` forces the bundle path.

Anchored exports additionally carry a monotonic manifest sequence, previous
manifest/history-head links, retained prior manifests, and a signed checkpoint
chain. Verification rejects deletion of any previously manifested record.
`--key` is now reported explicitly as the operator-identity trust boundary;
without it the result proves embedded-key integrity only. `--history-head` and
`--anchor-head` pin independently retained anti-rollback checkpoints.

## 0.7.0 (2026-06-12)

### Release rule for execution evidence

Bundles whose entries carry fills under an unreleased decision fail the
chain check: fills require an ALLOW parent, or an APPROVAL_REQUIRED
parent with a present approval whose decision is approved. A DENY or
REVIEW parent with fills always fails. Without this rule a bundle could
present individually valid signatures as evidence of an unauthorized
execution.

### Restraint receipts: prove what was prevented, offline and position-blind

A restraint receipt (`tool: gate.restrain`) is already verified as a Legate
governed receipt. This release re-verifies and surfaces its openable detail, so
the receipt proves not merely that a deny was signed but exactly WHAT was
prevented and WHY:

- The disclosed denial outcome (the determining rules, risk band, mandate
  digest) is re-hashed and confirmed to bind to the signed `result_sha256`, and
  the proposed blocked order is re-hashed under its salt and confirmed to bind to
  `input_sha256`. Re-hashing uses the same JCS canonicalization the runtime used,
  so altering the disclosed detail flips the binding to a failure while the
  signature stays valid over the original hashes (you cannot lie about what was
  blocked).
- Position-blind by construction: the blocked order can be withheld, and the
  outcome still verifies because the order is salt-committed into the signed input
  hash and openable to a regulator on demand.
- Terminal output gains a `Prevented:` block (risk band, determining rules, the
  blocked order or a position-blind note, and the two binding checks). New
  `verifyRestraintBindings` export. A sample lives at
  `samples/sample-restraint-receipt.json`; see `RESTRAINT-DEMO.md`.
- Added a `verify` bin alias (alongside `verify-artifact`) so
  `npx @veritasacta/verify <receipt>` reads naturally.

### ScopeBlind Gate receipt tuples and evidence bundles

New detected format and engine: `src/engines/gate-receipt.js` verifies
ScopeBlind Gate receipt tuples (`{ payload, digest, signature,
verification_key }`) and signed-manifest
`scopeblind.gate.evidence-bundle/2` exports, including their semantic
and exact chain links.

- Crypto contract: canonical form is deep-key-sorted JSON
  (`JSON.stringify(deepSort(payload))`, arrays keep order); `digest` is
  SHA-256 of the canonical UTF-8 bytes (lowercase hex); `signature` is
  Ed25519 over the 32 hex-decoded digest bytes, verified with the
  carried `verification_key`. Note this differs from the Acta receipt
  contract (JCS canonical bytes signed directly).
- Current bundle schema: `scopeblind.gate.evidence-bundle/2`. Its
  gate-signed manifest exactly enumerates every exported receipt digest
  and declares the retained-history scope. Legacy `/1` bundles are
  detected but fail closed because they cannot prove export
  completeness.
- Recognized payload schemas: `scopeblind.gate.decision/2`,
  `scopeblind.gate.batch/1`, `scopeblind.gate.batch-leg/1`,
  `scopeblind.gate.approval/1`, `scopeblind.gate.fill/1`,
  `scopeblind.gate.fill/2`, `scopeblind.gate.order-state/1`,
  `scopeblind.gate.evidence-manifest/1`, and
  `scopeblind.mandate.delegation/1`. Recognized schemas are validated
  semantically after cryptographic verification. Tuples with
  unknown `payload.schema` still crypto-verify as generic tuples and
  are reported as unrecognized (no hard fail).
- Bundle chain checks compare complete signed leg summaries, approval
  scope/state/determining rules, fill quantities and signed-leg
  digests, held-remainder authority, delegation holder/issuer/parent/
  child lineage, and the signed manifest's exact inventory. Crypto
  failures (`[crypto]`)
  and chain failures (`[chain]`) are counted and reported separately:
  a record can be individually authentic while its cross-record link
  is inconsistent.
- Signer report: distinct signing keys seen with their roles and whether
  all gate-authored receipts match the bundle's
  `gate_verification_key`. `--key` pins that trust anchor.
- Honest output: the report states what a VALID result proves
  (authenticity, integrity, schema validity, exact chain consistency,
  and manifest coverage) and what it does not (risk-input correctness,
  independent production corroboration for explicitly labeled demo
  fills, or records beyond the manifest's declared history scope).
- New error codes: `digest_mismatch`, `chain_link_mismatch`, and
  `schema_invalid` (tampered, exit 1), plus `key_mismatch` when a
  carried key differs from the `--key` pin.
- New modes `gate-receipt-tuple` and `gate-evidence-bundle` in
  detection, `--capabilities`, and forced dispatch (`--mode gate`,
  `--mode gate-bundle`).
- New samples signed with published deterministic demo keys:
  `samples/sample-gate-tuple.json`, `samples/sample-gate-bundle.json`.
- Focused unit tests in `test/unit/gate-receipt.test.js`; the signing
  side is implemented independently in the tests per the contract.

## 0.6.1 (2026-05-20)

Description-only release. No on-the-wire format change. No code change.

The npm description is updated to surface the broader deployment picture: this CLI is now the offline verification engine for protect-mcp (AI agent decision receipts), the ScopeBlind cold-chain evidence tag (NSW ETCF 2026 application #197, hardware programme in development), and Microsoft AI Agents for Beginners Lesson 18 (64K+ ★ curriculum): same primitive, three deployment contexts.

See [scopeblind.com/cold-chain](https://www.scopeblind.com/cold-chain) for the hardware programme and [github.com/microsoft/ai-agents-for-beginners/blob/main/18-securing-ai-agents/](https://github.com/microsoft/ai-agents-for-beginners/blob/main/18-securing-ai-agents/) for Lesson 18.

## 0.5.4 (2026-04-20): Rekor anchoring + hardware attestation + transparency profiles + watcher + SBOM bundles + AIP-0007

Ships the "differentiation roadmap" responding to the Signet / nono
feature-parity analysis. Thirteen new primitives across four strategic
tiers; none of them imitate Signet or nono: they extend the shipping
product to ground that only Veritas Acta holds.

### New AIP

- **AIP-0007** (Draft): Zero-Knowledge Compliance Proofs. Portable
  receipt-chain-level proof that every receipt adhered to a declared
  policy without revealing receipts. Target release: v0.7.0; the spec
  is committed now for public review.

### New engines

- **`src/engines/rekor.js`**: Transparency-log anchoring (AIP-0005 T4).
  Offline verification of Rekor / Sigstore inclusion proofs.
  RFC 6962 Merkle-path recomputation + Signed-Note signature
  verification. ISO 8601 duration parsing for `anchored_within`.
- **`src/engines/attestation-quote.js`**: Hardware-attestation quote
  validator (AIP-0005 T2). Dispatches to per-platform validators:
  ATECC608B (full crypto validator), Apple Secure Enclave (full),
  TPM2 / SGX / SEV-SNP / TDX (structural in v0.5.4; full crypto in v0.7).
  Enforces that `measured_kid` matches `signature.kid`.
- **`src/engines/watch.js`**: Live receipt watcher + webhook
  dispatcher. Rule kinds: `cost_tier_below`, `delegation_expiring_within`,
  `chain_break`, `deny_decision`, `scrub_triggered`. Slack / Discord /
  generic JSON payloads.
- **`src/engines/sbom.js`**: SBOM-audit bundle builder. Ingests SPDX /
  CycloneDX / unknown-format SBOMs; builds a deterministic
  `receipts_fingerprint` + canonical manifest; optional signing via
  caller-supplied callback.
- **`src/engines/transparency.js`**: Four profiles (private, auditable,
  transparent, high-assurance), profile-based anchor decisions, and a
  public-facing badge JSON format.

### New packages

- **`@veritasacta/cross-verify`**: Arbitrator tool for multi-format
  sessions. Extracts canonical `(tool, input_hash, issued_at)` tuples
  from Signet / Sigstore / Acta receipts and confirms agreement.
  Emits a SHA-256 agreement fingerprint. 19 unit tests.

### Ecosystem artifacts

- **`docs/voprf-issuance-for-implementers.md`**: Public pitch for
  competitors to route their T1 cost-tier through our commercial API.
- **`docs/framework-author-guide.md`**: Adoption onboarding for
  CrewAI / LangChain / Vercel AI / etc.
- **`docs/posts/infrastructure-not-competitor.md`**: Public letter to
  peer receipt-format projects articulating the infrastructure stance.
- **`docs/case-study-three-ecosystems.md`**: Microsoft + AWS +
  Anthropic contribution ledger.
- **`ecosystem/certify/`**: Weekly cross-implementation conformance
  certification program (workflow + runner skeleton).
- **`ecosystem/dashboard/`**: Upgraded with a DAG view for trace_id
  grouping.

### Tests

- 54 new unit tests: 12 Rekor, 11 attestation-quote, 12 watch, 7 sbom,
  14 transparency, 19 cross-verify (cross-verify is a separate package).
- verify-cli suite: **219 unit+integration + 26 conformance = 245 total**,
  all green.

### Sigil

- Historical bundled commitment: **Open Wind** (`677a8a81`).
- 36 source files monitored (up from 31 in v0.5.3).

## 0.5.3 (2026-04-20): delegation chains + bilateral cosign + trace_id + proxy hardening + dashboard

Responds to the Signet / nono comparison: adds the four receipt-shape
primitives that peer implementations have ("who authorized this
agent", "agent + server co-signed", "these receipts all belong to one
workflow", "receipts are visualisable") and the two proxy-layer
security primitives ("scrub secrets from captured args", "cosign the
same decision from two independent keys"). None of this requires new
cryptography. All composes with existing AIPs.

### New AIP

- **AIP-0006** (Draft): Delegation Chains. Defines a `delegation`
  receipt type conveying scoped, time-bounded, narrowing-only
  authority from a delegator to a delegate. Defines an
  `authorization.delegation_chain` payload field on action receipts
  referencing delegations by receipt_hash. Verifier walks to a trust
  anchor, checks signatures, expiry, scope subset, and max_depth at
  each hop.

### New engines

- **`src/engines/delegation.js`**: `verifyDelegationChain()` walks the
  chain from leaf to root, validating Ed25519 signatures against trust
  anchors, scope subset at each hop (narrowing-only), and the action's
  tool/target against the leaf's scope. 14 unit tests.
- **`src/engines/cosign.js`**: `verifyCosignatures()` + `attachCosignature()`.
  Envelope-level additive signatures. Each cosignature signs the SAME
  canonical payload bytes as the primary `signature`. Default semantic:
  all cosignatures must be resolved + valid; `requireAllValid: false`
  opt-in for M-of-N. 11 unit tests.
- **`src/engines/dashboard.js`**: `startDashboard()` spins up a
  loopback-only HTTP server serving `ecosystem/dashboard/` static + a
  `/api/receipts` JSON feed for a configured directory. DNS-rebinding
  defense (rejects non-loopback Host headers) and path-traversal
  defense. 6 smoke tests.

### New subcommand + CLI surface

- **`verify dashboard [--port 3847] [--bind 127.0.0.1] [--receipts-dir <dir>]`** : 
  Start the local dashboard. Opens immediately; no build step.
- **`verify proxy ... --bilateral --server-key <file>`**: Proxy now
  attaches a second independent signature (via `cosignatures[]`) to
  every receipt. Enables agent + server bilateral evidence without
  touching the primary signing path.
- **`verify proxy ... --scrub-secrets`**: Walks incoming tool args for
  probable-secret key names (`api_key`, `token`, `password`,
  `authorization`, etc.), redacts VALUES in the outgoing call, and
  flags the redacted paths on the receipt via `scrub_detected`. Secrets
  no longer enter the receipt even as a hash of the real value.
- **`verify proxy ... --trace-id <id>`**: Stamps every receipt with a
  workflow `trace_id` so multi-step flows group cleanly.

### Receipt-format extensions (non-breaking)

- **`trace_id`** + **`parent_receipt_id`** as optional AIP-0001 payload
  fields. `previousReceiptHash` remains the chain pointer; trace_id
  groups by workflow; parent_receipt_id expresses non-chain causal
  links. `chain explore` surfaces both; `groupByTrace(result)` buckets
  nodes by workflow.
- **`cosignatures: [{alg, kid, sig}, ...]`** as an optional
  envelope-level array. Old verifiers ignore it; v0.5.3+ verifiers
  check each one against caller-supplied trust anchors.
- **`authorization.delegation_chain: [<hash>...]`** as an optional
  AIP-0001 payload field. AIP-0006 verifiers walk it; others treat as
  opaque.

### Tests

- 41 new unit tests across this release: 14 delegation, 11 cosign,
  2 chain-explore trace, 8 proxy helpers, 6 dashboard.
- Full suite: **163 unit+integration + 26 conformance = 189 total**,
  all green.

### Sigil

- 31 source files monitored (up from 28 in v0.5.2). Historical bundled commitment:
  **Bright Lake** (`ea78b16e`).

## 0.5.2 (2026-04-20): compliance export + DSSE + BRASS v2 scaffold + AIP-0004/0005

Ships alongside v0.5.1 as the "governance surface fill" release. Adds
the compliance export subcommand, Sigstore DSSE envelope engine,
BRASS v2 hardening scaffold, and reference implementations for two new
AIPs.

### New subcommand

- **`verify compliance --receipts-dir <dir>`**: bucket a directory of
  receipts into SOC 2 / ISO 42001 / EU AI Act controls and emit an
  auditor-ready JSON bundle or self-contained HTML report. Supports
  `--framework soc2|iso42001|eu-ai-act|all`, `--start-date`, `--end-date`,
  `--org`, `--output`. Zero-evidence controls are surfaced explicitly
  so the auditor sees gaps rather than hidden silences.

### New engines

- **`src/engines/dsse.js`**: Dead Simple Signing Envelope (DSSE) wrap /
  unwrap / verify. Produces and consumes Sigstore-compatible envelopes
  with payload types `application/vnd.acta.receipt+json`,
  `application/vnd.acta.knowledge-unit+json`, or the standard in-toto
  statement type. Signatures bind to the DSSE pre-authentication
  encoding (PAE), not the raw payload.
- **`src/util/voprf-crypto-v2.js`**: BRASS v2 scaffold: length-prefixed
  hashing (`H_LP`), nullifier derivation bound to issuer public key Y
  (`deriveNullifier_v2`), single-variable πC restatement
  (`piCVerify_v2`). Not wired into the default path; accessible to
  implementers and exercised by unit tests.

### New AIPs

- **AIP-0004** (Draft): Content-Addressed Snapshot and Rollback
  Receipts. Defines `snapshot` and `rollback` receipt types with a
  Merkle root over file-content hashes. Reference implementation at
  `ecosystem/rollback/snapshot.mjs`; schema at
  `ecosystem/rollback/snapshot-receipt.schema.json`.
- **AIP-0005** (Draft): Attestation Weight Profile. Defines a
  portable `cost_tier` (T0–T4) over receipts, substantiated by VOPRF
  tokens (T1), hardware quotes (T2), multi-party signatures (T3), or
  transparency-log anchoring (T4). Reference implementation notes at
  `ecosystem/physical-attestation/DESIGN.md` + attestation-quote
  schema.

### Ecosystem additions

- **`ecosystem/wshobson-plugin/protect-mcp/`**: PR-ready Claude Code
  plugin tree for `wshobson/agents` marketplace. Closes issue #471.
  Ships agents (`policy-enforcer`, `receipt-verifier`), skill
  (`protect-mcp-setup`), slash commands (`/verify-receipt`,
  `/audit-chain`), and hooks.json.
- **`ecosystem/dashboard/index.html` + `dashboard.js`**: local-first
  in-browser audit dashboard scaffold. JCS + chain-integrity check
  over dropped receipts; renders `verify --json` output. No server,
  no telemetry.
- **`ecosystem/physical-attestation/DESIGN.md`**: physical-digital
  causal chain design for Seal hardware cost_tier T2 receipts.

### Sigil + tests

- Sigil commitment expanded to **28 source files** (adds compliance
  export, DSSE engine, v2 crypto util). Historical bundled commitment: **New Ember**
  (`b28f8d60`).
- 41 new unit tests across prompt, chain-explore, snapshot, compliance,
  DSSE, and BRASS v2 (11 of 41 new in this release).
- Full suite: **122 unit+integration + 26 conformance**: 148 total,
  all green.

## 0.5.1 (2026-04-20): prompt provenance + chain explorer + 5 sandbox profiles

### New subcommands

- **`verify prompt <file>`**: verify the provenance of a prompt/skill/system-instruction file against a Veritas Acta receipt asserting its SHA-256, a Sigstore DSSE bundle with an in-toto subject, or an `--expected-hash`. Closes the supply-chain attack vector where an attacker modifies `CLAUDE.md`, `SKILLS.md`, `AGENTS.md`, or a system prompt between authoring and agent runtime.
- **`verify chain explore <receipt>`**: walk the `previousReceiptHash` chain back to its root, validating every hash link. Emits a depth-annotated ASCII tree in terminal mode, structured JSON in `--json` mode. `--search-dir <dir>` overrides the ancestor search directory; `--max-depth N` caps the walk.

### Sigil commitment expansion

- Sigil v0.5.1 covered **25 source files** (up from 24 in v0.5.0): added `src/engines/prompt.js` + `src/engines/chain-explore.js`. Historical bundled commitment: **Bright Star** (`1cc829ab`).

### Ecosystem profiles

- **`ecosystem/profiles/`** ships pre-built sandboxing profiles for five common agent runtimes: Claude Code, Cursor, Codex, Gemini CLI, OpenClaw. Each ships `profile.yaml` + `policy.cedar` + `nono-capabilities.yaml` + `README.md` with threat-model notes. Composes with `sb-runtime --ring N --policy ./policy.cedar` and `nono run --caps ./nono-capabilities.yaml` for defense-in-depth.

### Tests

- 20 new unit tests: 10 for `verifyPrompt` (expected-hash / receipt / Sigstore / missing-source / error paths), 10 for `exploreChain` / `renderChainTree` (3-receipt chain, tamper detection, missing ancestor, maxDepth, searchDir override).
- Full suite now: **81 unit+integration + 26 conformance**: 107 total.

## 0.5.0 (2026-04-19): unified verifier + network-effect mechanics

### Network-effect mechanics

- **`--attest`** produces a self-signed local-integrity attestation: a signed
  JSON artifact the user can publish anywhere to demonstrate they ran
  local bytes matching the bundled public commitment. Fully offline,
  user-signed, opt-in; it does not authenticate the publisher.
  `--attest-org <name>` attaches an attributable identifier.
  `--attest-key <file>` overrides the default key location
  (`~/.veritasacta-verify/attester.json`).
- **`--emit-verification-receipt`** produces a signed receipt of a
  specific verification event: "this attester reported that this verifier
  returned valid at time T." Composable with Sigstore Rekor.

### Enterprise features

- **`--pin-sigil <fingerprint>`** enforces that the installed verifier
  matches a specific Sigil. Fails fast with exit code 2 and a clear
  message on mismatch. Supply-chain pinning for regulated deployments.
- **`--audit-log <file>`** appends every verification event to a local
  JSONL file with chain-linked hashes. Tamper-evident local audit trail
  for SIEM integration. Fully offline; nothing phoned home.
- **`--fips`** enforces FIPS 140-3 approved algorithms only. Currently
  rejects Ed25519 (pending NIST approval) with a clear migration
  message pointing at hybrid `ed25519+ml-dsa-65` (v0.6+).
- **`--replay-chain <file>`** bulk-verifies every receipt in a JSONL
  chain. Reports total / verified / failed / chain-breaks. Chain
  linkage (`previousReceiptHash`) is explicitly validated.
- **`--diff <other-file>`** structural diff between two receipts.
  Surfaces added/removed/changed fields, canonical hash comparison,
  and signature equality. Debugging aid for implementers.
- **`--audit-report`** renders a self-contained HTML audit report
  suitable for delivery to auditors / compliance teams / counterparties.
  Embeds the self-signed local-integrity attestation if `--attest` is also set.
  Includes verification summary, per-receipt breakdown, verifier
  provenance, and raw JSON result.
- **`--output <file>`** writes HTML reports or attestation JSON to a
  file instead of stdout.

### Sigil commitment expansion

- Sigil v0.5.0 commits to **21 source files** (up from v0.3.0's single
  cli.js): cli.js + 20 engines/outputs/utils/context files. Any
  modification invalidates `--self-check`.

### New subcommands (bootstrap + integration)

- **`verify init`**: zero-config onboarding wizard. Auto-detects framework across 13 supported agents (Claude Code, Claude Agent SDK, Google ADK, CrewAI, Pydantic AI, AutoGen, Smolagents, LangChain JS/Py, LangGraph JS/Py, OpenAI Agents, Vercel AI). Generates keys, writes `.veritasacta/config.json`, emits next-steps. `--framework <name>` override, `--force` overwrite.
- **`verify proxy --target "<cmd>"`**: universal MCP proxy. Wraps any MCP server with signing. No code changes in server or agent; each `tools/call` emits a chain-linked receipt. Signet-parity.
- **`verify daemon`**: sidecar daemon on Unix socket. Language-agnostic signing API (`POST /sign`). One daemon handles receipts for any number of agents in any language.

### Ecosystem artifacts (`ecosystem/`)

Shipped (working code):

- `ecosystem/github-action/`: drop-in CI step (`VeritasActa/verify-action@v1`)
- `ecosystem/claude-code-plugin/`: one-click Claude Code plugin + SKILL.md
- `ecosystem/homebrew-tap/Formula/veritasacta-verify.rb`: `brew install veritasacta-verify`
- `ecosystem/sdk-js/`: `@veritasacta/sdk` tiny signing helper (JS)
- `ecosystem/sdk-py/`: `veritasacta-sdk` tiny signing helper (Python)
- `ecosystem/adapters/langchain/`: LangChain adapter with full `withReceipts()` implementation
- `ecosystem/adapters/{langgraph,crewai,openai-agents,vercel-ai,smolagents,pydantic-ai,autogen}/`: seven additional framework adapter scaffolds
- `ecosystem/registry-worker/`: `registry.veritasacta.com` Cloudflare Worker
- `ecosystem/badge-worker/`: `verify.veritasacta.com/badge/*` shields.io-compatible SVG badges
- `ecosystem/interop-leaderboard/workflow.yml`: weekly cross-implementation interop CI

Scaffolds (design docs, implementation pending):

- `ecosystem/cosign-compat/DESIGN.md`: v0.6.0 Sigstore compatibility
- `ecosystem/rollback/DESIGN.md`: filesystem snapshots + undo (nono-style)
- `ecosystem/supervisor/DESIGN.md`: runtime approval flows
- `ecosystem/reputation/DESIGN.md`: issuer reputation (complement to aeoess agent reputation)
- `ecosystem/dashboard/DESIGN.md`: web audit dashboard (Signet-style)
- `ecosystem/browser-extension/DESIGN.md`: Claude.ai / ChatGPT consumer reach
- `ecosystem/ebpf-observer/DESIGN.md`: kernel-level auto-instrumentation (highest novelty)
- `ecosystem/vscode-extension/`: editor integration (v0.5.1)
- `ecosystem/CONFORMANCE-CERTIFICATION.md`: commercial certification service design
- `ecosystem/SIGIL-NAMING.md` + `ecosystem/RELEASE-NAMING.md`: public brand convention + historical Sigil registry

## 0.5.0 core: 2026-04-19 (unified verifier)

### Major

- **Unified verifier.** Single Apache-2.0 binary now handles Ed25519
  signed receipts, VOPRF anonymous-credential tokens (full dual-DLEQ
  verification), Knowledge Unit bundles, and selective-disclosure
  receipts. Auto-detects input format; `--mode receipt|voprf|ku|
  bundle|auto` forces a specific engine.
- **Full VOPRF DLEQ verification.** Both the issuer proof (πI:
  log_G(Y) = log_M(Z)) and the client proof (πC: knowledge of the
  blinding scalar b such that M = b·P) are verified with Schnorr
  DLEQ reconstruction (`A1 = r·g1 + c·h1`, `A2 = r·g2 + c·h2`; check
  that the recomputed challenge equals c). The engine is byte-
  compatible with the production BRASS issuer at `api.scopeblind.com`
  and the production client SDK: tokens issued in production verify
  against this engine, and the engine rejects any tampered scalar,
  wrong issuer key, scope mismatch, or AAD-bound πC tampering.
- **`--allow-partial-voprf` flag** retained as a no-op for
  compatibility with the `_partial` flag that existed during the
  port. All VOPRF results in 0.5.0 are full verifications; the flag
  is documented as deprecated and scheduled for removal in v0.6.0.
- **Modular architecture.** cli.js is a thin dispatcher; verification
  logic lives in `src/engines/*.js`. Each engine is independently
  auditable and testable.
- **Conformance tiers (T1-T5).** The verifier reports which tier of
  conformance a receipt exercised: T1 basic (Ed25519 + JCS + chain),
  T2 disclosure (AIP-0002), T3 attestation (hardware / anchor_uri),
  T4 privacy (VOPRF + holder_binding), T5 full (ZK compliance, v1.0+).
  Each verification surfaces the tier achieved.
- **Knowledge Unit bundles.** First-class support for
  draft-farley-acta-knowledge-units-00 multi-model deliberation
  bundles. Reports topic, models, rounds, consensus level, dissent,
  and verifies each embedded receipt.
- **AIP-0002 selective disclosure.** `--disclose field:salt:value`
  verifies salted SHA-256 commitments on redacted fields without
  needing the issuer. Redacted fields are counted and surfaced.
- **Sigil claim 2: live-context verification (patent #5).**
  `--require-context clock:±5s` / `geofence:...` / `sensor:temp<18`
  evaluates predicates at verification time. The verifier aggregates
  results and fails verification when any required predicate fails.
- **Sigil commits to entire codebase.** Previously Sigil only
  committed to cli.js. v0.5.0 extends commitment to all 15 source
  files (cli.js + src/engines/* + src/output/* + src/util/* +
  src/context/*). Modification of any file invalidates `--self-check`.
- **JSON output.** `--json` emits structured results including
  `tier`, `mode`, `algorithm`, `kid`, `key_source`, and
  `sigil_fingerprint` for machine consumption.
- **`--capabilities` command.** Lists supported modes, algorithms,
  tiers, specs, and wayfinding. For CI integration and compatibility
  discovery.
- **Error code registry.** Every emitted error code is stable,
  documented in ERRORS.md, and includes a spec section reference
  where applicable.

### Field recognition (surfaced in output, no verification required)

- `disclosure_mode` enum
- `holder_binding` object (modes: jwk_thumbprint, dpop,
  attested_credential; per AIP-0003)
- `annex_hash` (private annex commitment)
- `attestation_mode` (software, hardware:secure_element, hardware:tee,
  hardware:hsm)
- `anchor_uri` (transparency log anchor URI)
- Extended decision enum (challenge, payment_required, escalate,
  override)
- `nullifier` (VOPRF mode)
- `scope` structure (origin, epoch, sub)
- `compliance_credit_ref` (reserved for v1.0 ZK compliance proofs)
- `transport_hint` (direct, ohttp, tor, custom)
- `verifier_salt_kid` (VOPRF mode)

### Hybrid post-quantum

- Verifier detects `algorithm` values of the form `ed25519+ml-dsa-65`,
  `ed25519+dilithium3`, etc., and emits a clear `unsupported_algorithm`
  error. Full hybrid PQ verification is planned for v0.6+.

### Security

- Embedded-key rejection (from 0.4.0) retained. The deprecated
  `--allow-embedded-key` escape hatch is still present in 0.5.0 but
  will be removed in 0.6.0.
- `--strict` mode disables all deprecated fallbacks.
- Constant-time signature comparison preserved.

### Spec alignment

- Targets draft-farley-acta-signed-receipts-03 (Sigil self-check
  output now references -03 explicitly).
- References draft-farley-acta-knowledge-units-00 as the KU format.
- References AIP-0001 (receipt format), AIP-0002 (selective
  disclosure), AIP-0003 (holder binding).

### Supply chain

- Published with `npm publish --provenance` (Sigstore-anchored
  supply chain attestation).
- Dependency tree: `@veritasacta/artifacts` only. Transitive surface:
  `@noble/curves`, `@noble/hashes`.

### Documentation

- THREAT-MODEL.md: formal threat model covering tamper detection,
  replay, forgery, canonicalization, and the explicit non-goals.
- SECURITY.md: disclosure policy and supported-version matrix.
- ERRORS.md: complete error-code registry with spec references.
- Expanded README with conformance tiers and usage examples for
  every mode.

## 0.4.0 (2026-04-19): embedded-key rejection

### Security

- **Breaking change: embedded keys in receipt payloads are now
  rejected by default.** A verification key transported inside the
  signed payload does not provide authenticity against tampering
  (see draft-farley-acta-signed-receipts-03 Security Considerations).
- **New flag: `--allow-embedded-key`** (deprecated; removed in 0.5
  or 0.6). Restores pre-0.4.0 behaviour for one release cycle.
- Issue surfaced publicly by @desiorac on GetBindu PR #459.

## 0.3.0 (2026-04-05): previous release

Offline receipt verification via `@veritasacta/verify` CLI.
