# @veritasacta/langchain

LangChain / LangGraph adapter for Veritas Acta signed decision receipts.

**Apache-2.0 · JS + Python · Runs alongside any LangChain agent**

## Install

```bash
# JavaScript / TypeScript
npm install @veritasacta/langchain @veritasacta/sdk

# Python
pip install veritasacta-langchain veritasacta-sdk
```

## Usage — JavaScript

```ts
import { ChatOpenAI } from '@langchain/openai';
import { AgentExecutor, createReactAgent } from 'langchain/agents';
import { Signer } from '@veritasacta/sdk';
import { withReceipts } from '@veritasacta/langchain';

const signer = Signer.fromKeyFile('.veritasacta/attester.json');

const agent = createReactAgent({
  llm: new ChatOpenAI(),
  tools,
});

// Wrap any AgentExecutor to emit a signed receipt on every tool call
const auditedAgent = withReceipts(agent, {
  signer,
  policyId: 'research-read-only-v1',
  receiptsDir: '.veritasacta/receipts',
});

const result = await auditedAgent.invoke({ input: 'What happened this week?' });
// Each tool call produced a signed receipt under .veritasacta/receipts/
```

## Usage — Python

```python
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_react_agent
from veritasacta_sdk import Signer
from veritasacta_langchain import with_receipts

signer = Signer.from_key_file(".veritasacta/attester.json")

agent = create_react_agent(llm=ChatOpenAI(), tools=tools)

audited = with_receipts(
    agent,
    signer=signer,
    policy_id="research-read-only-v1",
    receipts_dir=".veritasacta/receipts",
)

result = audited.invoke({"input": "What happened this week?"})
```

## How it works

`withReceipts` / `with_receipts` wraps LangChain's tool-invocation path
(via the `on_tool_start` / `on_tool_end` callbacks) and calls
`signer.signDecision({...})` for each tool invocation. The returned
receipt is persisted to the configured receipts directory; verification
happens later with `npx @veritasacta/verify`.

## Field mapping

| LangChain concept | Veritas Acta field |
|---|---|
| Tool name | `tool_name` |
| Tool arguments (hashed) | `tool_input_hash` |
| Output (hashed, optional) | `output_hash` |
| Policy label | `policy_id` |
| Agent identity | `agent_id` |
| Chain link | `previousReceiptHash` |

## Verifying

```bash
npx @veritasacta/verify .veritasacta/receipts/*.json --key <pubkey>
```

## Related

- [@veritasacta/verify](https://www.npmjs.com/package/@veritasacta/verify) — the verifier
- [@veritasacta/sdk](https://www.npmjs.com/package/@veritasacta/sdk) — the underlying signer
- [Veritas Acta protocol](https://veritasacta.com)

## License

Apache-2.0
