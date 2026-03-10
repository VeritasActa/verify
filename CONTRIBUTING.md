# Contributing to @veritasacta/verify

Thanks for your interest in contributing to Veritas Acta.

## Getting Started

```bash
git clone https://github.com/VeritasActa/verify.git
cd verify
npm install
npm test
```

## Development

This project uses:
- **Node.js** (ESM modules)
- **Vitest** for testing
- **@noble/curves** and **@noble/hashes** for cryptography

### Running Tests

```bash
npm test            # Run all 75 tests once
npm run test:watch  # Watch mode
```

### Project Structure

```
src/
├── index.js          # Barrel exports
├── crypto.js         # Deterministic crypto primitives (pure functions)
├── verifier.js       # Core verify() logic
├── storage.js        # Abstract counter store interface
└── adapters/
    ├── memory-store.js   # In-process store (testing)
    └── kv-store.js       # Cloudflare KV store
test/
├── crypto.test.js        # 65 tests for crypto primitives
└── memory-store.test.js  # 10 tests for MemoryStore
examples/
├── express-middleware.js  # Express integration
└── cloudflare-worker.js   # Cloudflare Worker integration
```

## Guidelines

1. **All functions in `crypto.js` must be pure** — no side effects, no I/O, no global state.
2. **All cryptographic operations** must use `@noble/curves` and `@noble/hashes`. No custom crypto.
3. **Every new function needs tests.** Aim for determinism tests (same input = same output) and isolation tests (different scopes produce different results).
4. **No new runtime dependencies** unless absolutely necessary and audited.

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b my-feature`)
3. Write tests for your changes
4. Ensure all tests pass (`npm test`)
5. Submit a pull request with a clear description

## Security

If you find a security vulnerability, please do **not** open a public issue. Instead, email [security@veritasacta.com](mailto:security@veritasacta.com). See [SECURITY.md](./SECURITY.md) for details.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](./LICENSE).
