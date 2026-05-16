# Veritas Acta Verify — VS Code Extension (scaffold)

Planned v0.5.1+ artifact. Provides:

- **Syntax highlighting** for `.receipt.json` files
- **On-save verification** using the installed `@veritasacta/verify` CLI
- **Sigil art in status bar** when editing a receipt
- **Hover tooltips** showing field meaning + spec references
- **Command palette entries**:
  - `Veritas Acta: Verify current file`
  - `Veritas Acta: Self-check installed verifier`
  - `Veritas Acta: Generate sample receipt`
  - `Veritas Acta: Show Sigil`

## Implementation sketch

TypeScript / Node.js VS Code extension. Uses the installed CLI via
`child_process`; no in-extension crypto.

```
vscode-extension/
├── package.json           # extension manifest
├── src/
│   ├── extension.ts       # activate / commands
│   ├── diagnostics.ts     # run verifier on save, attach problems
│   ├── hover.ts           # field tooltips citing spec sections
│   └── statusBar.ts       # Sigil fingerprint in status bar
├── language-config.json   # Receipt JSON language config
└── README.md
```

## v0.5.0 placeholder

This scaffold is documentation-only today. Implementation is tracked
for v0.5.1 / v0.6.0.

## License

Apache-2.0 (once shipped).
