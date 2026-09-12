# The one-command restraint demo

The point in one sentence: most governance can only prove what an agent **did**.
This proves, offline and with no vendor trust, what an agent was **prevented**
from doing.

## The command

From `packages/verify-cli` (works right now, local):

```
node cli.js samples/sample-restraint-receipt.json
```

The published one-liner (after the next npm publish, see below):

```
npx @veritasacta/verify samples/sample-restraint-receipt.json
```

That is the whole demo. One command. No servers contacted.

## What the viewer sees, and what to say

1. **A Sigil renders, then `Signature: VALID`.** "This is a signed receipt from a
   live gate. The verifier is open source, Apache-2.0, and it just checked the
   Ed25519 signature with zero of our code and no network."
2. **`Prevented:` block.** "Here is what the gate stopped: a 2 million dollar
   single-name order the agent's own authority manifest forbids. Risk band:
   authority. These are the exact rules that fired."
3. **The two green checks.** "And here is the part nobody else has. The verifier
   re-hashes the disclosed outcome and the blocked order, and confirms they bind
   to the signed hashes. So this is not a screenshot or a log we could have
   edited. The detail you are reading is provably the detail that was signed."
4. **`No servers were contacted.`** "A regulator, an LP, or a counterparty can run
   this themselves, offline, and get the same answer. Trust the math, not us."

## The second beat: watch it catch a forgery

Optional, and it lands hard. Alter the disclosed detail and run it again:

```
# claim the blocked order was smaller than it was, then verify
node -e "const fs=require('fs');const r=JSON.parse(fs.readFileSync('samples/sample-restraint-receipt.json'));r.restraint.proposed.notional=1;fs.writeFileSync('/tmp/forged.json',JSON.stringify(r))"
node cli.js /tmp/forged.json
```

The signature stays `VALID` (the signed hashes were not touched), but the binding
line flips to a red `✗`: "the disclosed order no longer re-hashes to the signed
input hash." You cannot lie about what was blocked. Say: "If anyone edits the
proof, the proof says so."

## Position-blind (a strong aside)

The receipt is position-blind capable: withhold the order and the outcome still
verifies, because the order is salt-committed into the signed input hash and
openable to a regulator on demand. To show it:

```
node -e "const fs=require('fs');const r=JSON.parse(fs.readFileSync('samples/sample-restraint-receipt.json'));r.restraint.proposed=null;fs.writeFileSync('/tmp/blind.json',JSON.stringify(r))"
node cli.js /tmp/blind.json
```

"The desk can prove it was restrained without disclosing the position itself."

## Before you record the `npx` one-liner

The enhanced presentation ships in this working copy but not yet on npm. To make
`npx @veritasacta/verify ...` show it, publish the new version first (your step,
needs npm credentials):

```
npm publish   # from packages/verify-cli, version 0.7.0
```

Until then, record with `node cli.js ...`, which is identical output.

## How the sample was made

`samples/sample-restraint-receipt.json` is a real signed receipt, minted by the
actual gate from a real deny (an agent authority manifest forbidding the
instrument). To regenerate it from the monorepo:

```
node samples/generate-restraint-sample.mjs
```
