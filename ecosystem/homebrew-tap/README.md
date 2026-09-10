# VeritasActa Homebrew Tap

Install `@veritasacta/verify` via Homebrew.

## Usage

```bash
brew tap VeritasActa/verify
brew install veritasacta-verify
```

After install:

```bash
verify --self-check
verify init
verify samples/sample-receipt.json --key <pubkey>
```

## Formula

See `Formula/veritasacta-verify.rb`. The formula wraps `npm install -g @veritasacta/verify` with a Sigil self-check. That check compares local bytes with the commitment bundled in the same installation. It does not authenticate the publisher unless the expected fingerprint is obtained independently and pinned.

## Deployment

This directory is the source for the `VeritasActa/homebrew-verify` GitHub repo. To publish:

```bash
cd ecosystem/homebrew-tap
gh repo create VeritasActa/homebrew-verify --public --source=. --push
```

## License

Apache-2.0
