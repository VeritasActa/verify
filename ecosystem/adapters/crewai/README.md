# veritasacta-crewai

CrewAI adapter for Veritas Acta signed receipts. Wraps Task / Agent
tool invocations in CrewAI so every tool call emits a signed receipt.

## Status

v0.1.0 scaffold. Intended for users running CrewAI crews who want
independently verifiable evidence of agent decisions.

## Install

```bash
pip install veritasacta-crewai veritasacta-sdk
```

## Usage

```python
from crewai import Agent, Task, Crew
from veritasacta_sdk import Signer
from veritasacta_crewai import attach_receipts

signer = Signer.from_key_file(".veritasacta/attester.json")

crew = Crew(agents=[...], tasks=[...])
attach_receipts(crew, signer=signer, policy_id="research-v1", receipts_dir=".veritasacta/receipts")

result = crew.kickoff()
# Every task/tool invocation produced a receipt under .veritasacta/receipts
```

## Verification

```bash
npx @veritasacta/verify .veritasacta/receipts/*.json --key <pubkey>
```

## License

Apache-2.0
