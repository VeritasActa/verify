export interface SignDecisionInput {
  tool: string;
  args?: Record<string, unknown>;
  decision?: 'allow' | 'deny' | 'require_approval' | 'compensated' | string;
  policy_id?: string;
  policy_hash?: string;
  skill_version_hash?: string;
  delegation_chain_root?: string;
  metadata?: Record<string, unknown>;
}

export interface Receipt {
  payload: Record<string, unknown>;
  signature: { alg: string; kid: string; sig: string };
}

export class Signer {
  readonly kid: string;
  readonly pubHex: string;
  readonly issuerId: string;
  sequence: number;
  previousReceiptHash: string | null;

  static fromKeyFile(path: string): Signer;
  signDecision(input: SignDecisionInput): Receipt;
}
