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

See `Formula/veritasacta-verify.rb`. The formula wraps `npm install -g @veritasacta/verify` with a Sigil self-check step on post-install, so every Homebrew installation cryptographically confirms it got the canonical release.

## Deployment

This directory is the source for the `VeritasActa/homebrew-verify` GitHub repo. To publish:

```bash
cd ecosystem/homebrew-tap
gh repo create VeritasActa/homebrew-verify --public --source=. --push
```

## License

Apache-2.0
