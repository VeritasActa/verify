# @veritasacta/openai-agents

OpenAI Agents SDK adapter for Veritas Acta signed receipts.

## Status

v0.1.0 scaffold. Composes with the [on_tool_authorize hook proposal
(openai/openai-agents-python#2868)](https://github.com/openai/openai-agents-python/issues/2868).

## Install

```bash
# JS
npm install @veritasacta/openai-agents @veritasacta/sdk

# Python
pip install veritasacta-openai-agents veritasacta-sdk
```

## Usage

```ts
import { Agent } from '@openai/agents';
import { Signer } from '@veritasacta/sdk';
import { attachReceipts } from '@veritasacta/openai-agents';

const signer = Signer.fromKeyFile('.veritasacta/attester.json');

const agent = new Agent({
  name: 'researcher',
  tools: [...],
});

attachReceipts(agent, {
  signer,
  policyId: 'research-v1',
  receiptsDir: '.veritasacta/receipts',
});

await agent.run({ input: '...' });
```

## License

Apache-2.0
