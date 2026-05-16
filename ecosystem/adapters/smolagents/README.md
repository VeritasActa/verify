# veritasacta-smolagents

Smolagents (HuggingFace) adapter for Veritas Acta signed receipts.

## Status

v0.1.0 scaffold.

## Install

```bash
pip install veritasacta-smolagents veritasacta-sdk
```

## Usage

```python
from smolagents import CodeAgent
from veritasacta_sdk import Signer
from veritasacta_smolagents import ReceiptHook

signer = Signer.from_key_file(".veritasacta/attester.json")

agent = CodeAgent(
    tools=[...],
    hooks=[ReceiptHook(signer, policy_id="research-v1")],
)

agent.run("...")
```

## License

Apache-2.0
