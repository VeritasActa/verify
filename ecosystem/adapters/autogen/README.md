# veritasacta-autogen

> **Reference material:** This integration is not release-qualified by the core verifier CI.
> Commands, package versions and deployment claims below may be historical.
> Read the [current ecosystem status](../../README.md) before using it.


Microsoft AutoGen adapter for Veritas Acta signed receipts.

## Status

v0.1.0 scaffold.

## Install

```bash
pip install veritasacta-autogen veritasacta-sdk
```

## Usage

```python
from autogen_agentchat.agents import AssistantAgent
from veritasacta_sdk import Signer
from veritasacta_autogen import attach_receipts

signer = Signer.from_key_file(".veritasacta/attester.json")

agent = AssistantAgent(name="assistant", tools=[...])
attach_receipts(agent, signer=signer, policy_id="chat-v1")

await agent.run(task="...")
```

## License

Apache-2.0
