/**
 * @veritasacta/langchain — LangChain adapter for signed receipts.
 *
 * Wraps a LangChain AgentExecutor (or any runnable with tool
 * invocations) by attaching callback handlers that emit Veritas Acta
 * receipts on every tool call.
 *
 * @license Apache-2.0
 */

import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

class ReceiptsCallbackHandler {
  constructor({ signer, policyId, receiptsDir, agentId }) {
    this.signer = signer;
    this.policyId = policyId;
    this.receiptsDir = receiptsDir;
    this.agentId = agentId;
    if (!existsSync(receiptsDir)) mkdirSync(receiptsDir, { recursive: true });
  }

  async handleToolStart(tool, input) {
    // Cache for use at end
    this._pending = { tool, input, startedAt: Date.now() };
  }

  async handleToolEnd(output) {
    if (!this._pending) return;
    const { tool, input } = this._pending;
    const toolName = tool?.name || tool?.lc_id || 'unknown-tool';

    const receipt = this.signer.signDecision({
      tool: toolName,
      args: typeof input === 'string' ? { input } : input,
      decision: 'allow',
      policy_id: this.policyId,
      metadata: this.agentId ? { agent_id: this.agentId } : undefined,
    });

    const filename = `rcpt_${String(this.signer.sequence).padStart(6, '0')}.json`;
    writeFileSync(join(this.receiptsDir, filename), JSON.stringify(receipt, null, 2));
    this._pending = null;
  }

  async handleToolError(err) {
    if (!this._pending) return;
    const { tool, input } = this._pending;
    const toolName = tool?.name || 'unknown-tool';
    const receipt = this.signer.signDecision({
      tool: toolName,
      args: typeof input === 'string' ? { input } : input,
      decision: 'deny',
      policy_id: this.policyId,
      metadata: { error: err?.message || 'unknown' },
    });
    const filename = `rcpt_${String(this.signer.sequence).padStart(6, '0')}.json`;
    writeFileSync(join(this.receiptsDir, filename), JSON.stringify(receipt, null, 2));
    this._pending = null;
  }
}

/**
 * Wrap a LangChain AgentExecutor or Runnable with receipt emission.
 *
 * @param {Object} agent      LangChain agent / runnable
 * @param {Object} opts
 * @param {Object} opts.signer       @veritasacta/sdk Signer instance
 * @param {string} [opts.policyId]
 * @param {string} [opts.receiptsDir='.veritasacta/receipts']
 * @param {string} [opts.agentId]
 * @returns {Object} wrapped agent
 */
export function withReceipts(agent, opts) {
  const handler = new ReceiptsCallbackHandler({
    signer: opts.signer,
    policyId: opts.policyId || 'veritasacta:langchain:default',
    receiptsDir: opts.receiptsDir || '.veritasacta/receipts',
    agentId: opts.agentId,
  });

  // LangChain lets us attach callbacks via .withConfig / .bind / invoke({callbacks})
  // The wrap is intentionally minimal: any place that accepts a callbacks list
  // will fire our handlers.
  const original = agent.invoke ? agent.invoke.bind(agent) : null;
  if (!original) {
    throw new Error('withReceipts: agent does not expose .invoke(); wrap a different object.');
  }

  return {
    ...agent,
    invoke(input, config = {}) {
      const callbacks = [...(config.callbacks || []), handler];
      return original(input, { ...config, callbacks });
    },
  };
}

export { ReceiptsCallbackHandler };
