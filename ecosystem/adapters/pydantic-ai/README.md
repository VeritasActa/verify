# veritasacta-pydantic-ai

Pydantic AI adapter for Veritas Acta signed receipts. Wraps `Agent.tool`
decorators with signing callbacks.

## Status

v0.1.0 scaffold.

## Install

```bash
pip install veritasacta-pydantic-ai veritasacta-sdk
```

## Usage

```python
from pydantic_ai import Agent
from veritasacta_sdk import Signer
from veritasacta_pydantic_ai import with_receipts

signer = Signer.from_key_file(".veritasacta/attester.json")

agent = Agent("openai:gpt-4o")
with_receipts(agent, signer=signer, policy_id="chat-v1")

@agent.tool
def my_tool(ctx, x: int) -> int:
    return x * 2

result = agent.run_sync("...")
```

## License

Apache-2.0
