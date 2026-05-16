# @veritasacta/vercel-ai

Vercel AI SDK adapter for Veritas Acta signed receipts. Wraps
`streamText` / `generateText` tool calls with signing hooks.

## Status

v0.1.0 scaffold. Works with the Vercel AI SDK's `tools` / `experimental_onToolCall` extension points.

## Install

```bash
npm install @veritasacta/vercel-ai @veritasacta/sdk
```

## Usage

```ts
import { streamText } from 'ai';
import { Signer } from '@veritasacta/sdk';
import { veritasactaMiddleware } from '@veritasacta/vercel-ai';

const signer = Signer.fromKeyFile('.veritasacta/attester.json');

const result = await streamText({
  model: myModel,
  tools: myTools,
  experimental_onToolCall: veritasactaMiddleware({
    signer,
    policyId: 'chat-v1',
    receiptsDir: '.veritasacta/receipts',
  }),
});
```

## License

Apache-2.0
