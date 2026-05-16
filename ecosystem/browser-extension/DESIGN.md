# Browser Extension (v0.6.0 target)

Chrome + Firefox extension that injects receipt generation into
consumer-facing AI interfaces (Claude.ai, ChatGPT, Anthropic Console,
Cursor web, Gemini). The first receipt primitive a non-developer can
use without touching a CLI.

## Goal

Enable ANY user of a public AI chat UI to produce cryptographic proof
of what the agent did, without needing CLI access, API integration, or
developer expertise. Consumer-grade reach.

## Design

### Activation

- User installs extension
- Extension detects the AI UI (domain matching)
- Extension injects observer scripts into the page DOM
- When a tool call is rendered (shown to the user), extension captures
  the structural metadata
- Extension signs a receipt client-side using a user-owned Ed25519 key
  (generated on first install, stored in browser localStorage /
  IndexedDB)

### Receipts

Receipts are stored locally (extension storage) during the session.
User can:

1. Export session as a JSONL chain
2. Upload to a personal receipt storage location (S3, Drive, Dropbox)
3. Publish as a canonical attestation

### UX

- Sigil badge in the browser toolbar showing the canonical verifier
  version + user's own kid
- Click to show current session's receipt count + chain integrity
- "Export session" button

## Browser support

- Chrome (MV3)
- Firefox (WebExtensions API)
- Edge (Chromium-based, works out of box with Chrome build)
- Safari (not planned for v0.6; Safari's extension API has more friction)

## Privacy

- No phone-home
- All receipts stay in local extension storage unless user explicitly
  exports
- Signing happens client-side with a key stored in extension storage
- User controls their own attestation identity

## Known limitations

- UI-level observation: can't see internal model reasoning
- Cosmetic-only DOM detection: a UI change could break capture
- Not a replacement for provider-supplied audit trails; user-owned
  complement

## License

Apache-2.0 once shipped.
