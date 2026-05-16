# @veritasacta/langgraph

LangGraph adapter for Veritas Acta signed receipts. Built on `@veritasacta/langchain`; exposes `withGraphReceipts()` that attaches receipt callbacks to every node execution in the graph.

## Status

v0.1.0 scaffold. Full implementation tracked alongside the LangChain adapter.

## Install

```bash
npm install @veritasacta/langgraph @veritasacta/sdk
```

## Usage

```ts
import { StateGraph } from '@langchain/langgraph';
import { Signer } from '@veritasacta/sdk';
import { withGraphReceipts } from '@veritasacta/langgraph';

const signer = Signer.fromKeyFile('.veritasacta/attester.json');

const graph = new StateGraph(...).compile();
const audited = withGraphReceipts(graph, { signer, policyId: 'graph-v1' });

await audited.invoke({ input: '...' });
// Each node invocation emits a receipt.
```

## License

Apache-2.0
