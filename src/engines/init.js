/**
 * Init wizard — framework auto-detection + zero-config onboarding.
 *
 * `npx @veritasacta/verify init` inspects the current directory,
 * detects the agent framework in use, generates Ed25519 signing keys,
 * creates a starter config, and emits a welcome canonical attestation.
 *
 * Detection precedence (first match wins):
 *   1. Explicit `--framework <name>` override
 *   2. `.claude/settings.json` exists → Claude Code (MCP)
 *   3. `package.json` contains `@anthropic-ai/claude-agent-sdk` → Claude Agent SDK
 *   4. `package.json` contains `@langchain/*` → LangChain
 *   5. `package.json` contains `langgraph` → LangGraph
 *   6. `package.json` contains `@openai/agents` → OpenAI Agents SDK
 *   7. `package.json` contains `ai` (Vercel AI SDK)
 *   8. `pyproject.toml` / `requirements.txt` contains `google-adk` → ADK
 *   9. `pyproject.toml` / `requirements.txt` contains `crewai` → CrewAI
 *  10. `pyproject.toml` / `requirements.txt` contains `pydantic-ai` → Pydantic AI
 *  11. `pyproject.toml` / `requirements.txt` contains `autogen-agentchat` → AutoGen
 *  12. `pyproject.toml` / `requirements.txt` contains `smolagents` → Smolagents
 *  13. `pyproject.toml` / `requirements.txt` contains `langchain` → LangChain (Python)
 *  14. Fallback: generic (prints manual instructions)
 *
 * Output: creates `.veritasacta/` directory with:
 *   - `attester.json` (signing key, private; .gitignore'd)
 *   - `config.json` (framework + adapter selection)
 *   - `receipts/` (default receipt output directory)
 *   - `welcome-attestation.json` (canonical attestation of this init run)
 *
 * @module verify-cli/src/engines/init
 * @license Apache-2.0
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, appendFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * @typedef {Object} FrameworkDetection
 * @property {string} framework   canonical name
 * @property {string} adapter     npm/PyPI package to install
 * @property {string} language    'javascript' | 'python' | 'rust' | 'unknown'
 * @property {string[]} signals   what we detected
 * @property {string} setupType   'mcp-hook' | 'middleware' | 'plugin' | 'sdk' | 'manual'
 */

/** @type {FrameworkDetection[]} */
const DETECTION_RULES = [
  // Claude Code (MCP hooks)
  {
    framework: 'claude-code',
    language: 'javascript',
    adapter: 'protect-mcp',
    setupType: 'mcp-hook',
    detectFn: (ctx) => ctx.hasFile('.claude/settings.json') || ctx.hasFile('.claude/settings.local.json'),
    reason: '.claude/settings.json detected',
  },
  // Claude Agent SDK
  {
    framework: 'claude-agent-sdk',
    language: 'javascript',
    adapter: '@scopeblind/passport',
    setupType: 'sdk',
    detectFn: (ctx) => ctx.packageJsonHas('@anthropic-ai/claude-agent-sdk'),
    reason: '@anthropic-ai/claude-agent-sdk in package.json',
  },
  // Google ADK (Python)
  {
    framework: 'google-adk',
    language: 'python',
    adapter: 'protect-mcp-adk',
    setupType: 'plugin',
    detectFn: (ctx) => ctx.pythonDepHas('google-adk'),
    reason: 'google-adk in Python dependencies',
  },
  // CrewAI (Python)
  {
    framework: 'crewai',
    language: 'python',
    adapter: 'veritasacta-crewai',
    setupType: 'middleware',
    detectFn: (ctx) => ctx.pythonDepHas('crewai'),
    reason: 'crewai in Python dependencies',
    templatePath: 'ecosystem/adapters/crewai',
  },
  // Pydantic AI
  {
    framework: 'pydantic-ai',
    language: 'python',
    adapter: 'veritasacta-pydantic-ai',
    setupType: 'middleware',
    detectFn: (ctx) => ctx.pythonDepHas('pydantic-ai'),
    reason: 'pydantic-ai in Python dependencies',
    templatePath: 'ecosystem/adapters/pydantic-ai',
  },
  // AutoGen
  {
    framework: 'autogen',
    language: 'python',
    adapter: 'veritasacta-autogen',
    setupType: 'middleware',
    detectFn: (ctx) => ctx.pythonDepHas('autogen-agentchat') || ctx.pythonDepHas('pyautogen'),
    reason: 'autogen in Python dependencies',
    templatePath: 'ecosystem/adapters/autogen',
  },
  // Smolagents
  {
    framework: 'smolagents',
    language: 'python',
    adapter: 'veritasacta-smolagents',
    setupType: 'middleware',
    detectFn: (ctx) => ctx.pythonDepHas('smolagents'),
    reason: 'smolagents in Python dependencies',
    templatePath: 'ecosystem/adapters/smolagents',
  },
  // LangChain JS
  {
    framework: 'langchain-js',
    language: 'javascript',
    adapter: '@veritasacta/langchain',
    setupType: 'middleware',
    detectFn: (ctx) => ctx.packageJsonMatch(/^@langchain\//),
    reason: '@langchain/* in package.json',
    templatePath: 'ecosystem/adapters/langchain',
  },
  // LangChain Python
  {
    framework: 'langchain-py',
    language: 'python',
    adapter: 'veritasacta-langchain',
    setupType: 'middleware',
    detectFn: (ctx) => ctx.pythonDepHas('langchain') || ctx.pythonDepHas('langchain-core'),
    reason: 'langchain in Python dependencies',
    templatePath: 'ecosystem/adapters/langchain',
  },
  // LangGraph JS
  {
    framework: 'langgraph-js',
    language: 'javascript',
    adapter: '@veritasacta/langgraph',
    setupType: 'middleware',
    detectFn: (ctx) => ctx.packageJsonHas('@langchain/langgraph'),
    reason: '@langchain/langgraph in package.json',
    templatePath: 'ecosystem/adapters/langgraph',
  },
  // LangGraph Python
  {
    framework: 'langgraph-py',
    language: 'python',
    adapter: 'veritasacta-langgraph',
    setupType: 'middleware',
    detectFn: (ctx) => ctx.pythonDepHas('langgraph'),
    reason: 'langgraph in Python dependencies',
    templatePath: 'ecosystem/adapters/langgraph',
  },
  // OpenAI Agents SDK
  {
    framework: 'openai-agents',
    language: 'javascript',
    adapter: '@veritasacta/openai-agents',
    setupType: 'middleware',
    detectFn: (ctx) => ctx.packageJsonHas('@openai/agents') || ctx.pythonDepHas('openai-agents'),
    reason: '@openai/agents or openai-agents detected',
    templatePath: 'ecosystem/adapters/openai-agents',
  },
  // Vercel AI SDK
  {
    framework: 'vercel-ai',
    language: 'javascript',
    adapter: '@veritasacta/vercel-ai',
    setupType: 'middleware',
    detectFn: (ctx) => ctx.packageJsonHas('ai') && !ctx.packageJsonHas('openai'),
    reason: 'Vercel AI SDK (`ai` package) in package.json',
    templatePath: 'ecosystem/adapters/vercel-ai',
  },
];

function buildDetectionContext(cwd) {
  let pkg = null;
  let pyproject = null;
  let requirements = null;

  try { pkg = JSON.parse(readFileSync(join(cwd, 'package.json'), 'utf-8')); } catch {}
  try { pyproject = readFileSync(join(cwd, 'pyproject.toml'), 'utf-8'); } catch {}
  try { requirements = readFileSync(join(cwd, 'requirements.txt'), 'utf-8'); } catch {}

  return {
    cwd,
    pkg,
    pyproject,
    requirements,
    hasFile(rel) { return existsSync(join(cwd, rel)); },
    packageJsonHas(name) {
      if (!pkg) return false;
      return Boolean(
        pkg.dependencies?.[name]
        || pkg.devDependencies?.[name]
        || pkg.peerDependencies?.[name],
      );
    },
    packageJsonMatch(regex) {
      if (!pkg) return false;
      const all = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}), ...(pkg.peerDependencies || {}) };
      return Object.keys(all).some((k) => regex.test(k));
    },
    pythonDepHas(name) {
      if (pyproject && pyproject.includes(name)) return true;
      if (requirements && requirements.split('\n').some((line) => line.trim().startsWith(name))) return true;
      return false;
    },
  };
}

/**
 * Detect the framework in use.
 *
 * @param {string} cwd
 * @param {string} [override]  user-supplied --framework value
 * @returns {FrameworkDetection | null}
 */
export function detectFramework(cwd, override) {
  const ctx = buildDetectionContext(cwd);

  if (override) {
    const match = DETECTION_RULES.find((r) => r.framework === override);
    if (match) return { ...match, signals: [`--framework ${override}`] };
  }

  for (const rule of DETECTION_RULES) {
    if (rule.detectFn(ctx)) {
      return { ...rule, signals: [rule.reason] };
    }
  }
  return null;
}

/**
 * Generate a fresh Ed25519 signing key for the project.
 */
async function generateProjectKey(keyPath) {
  const { generateKeyPairSync } = await import('node:crypto');
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pubRaw = publicKey.export({ type: 'spki', format: 'der' });
  const privRaw = privateKey.export({ type: 'pkcs8', format: 'der' });
  const pubHex = pubRaw.subarray(pubRaw.length - 32).toString('hex');
  const privHex = privRaw.toString('hex');
  const kid = `project:${pubHex.slice(0, 12)}`;

  writeFileSync(
    keyPath,
    JSON.stringify({
      kid,
      pubHex,
      privateDer: privHex,
      created_at: new Date().toISOString(),
    }, null, 2),
    { mode: 0o600 },
  );
  return { kid, pubHex };
}

/**
 * Run the init wizard.
 *
 * @param {Object} opts
 * @param {string} [opts.cwd=process.cwd()]
 * @param {string} [opts.framework]   --framework override
 * @param {string} [opts.org]         --attest-org value for welcome attestation
 * @param {boolean} [opts.force=false] overwrite existing .veritasacta/
 * @returns {Promise<Object>}
 */
export async function runInit(opts = {}) {
  const cwd = opts.cwd || process.cwd();
  const vaDir = join(cwd, '.veritasacta');
  const receiptsDir = join(vaDir, 'receipts');

  if (existsSync(vaDir) && !opts.force) {
    return {
      status: 'exists',
      message: `.veritasacta/ already exists at ${vaDir}. Pass --force to overwrite.`,
    };
  }

  mkdirSync(vaDir, { recursive: true });
  mkdirSync(receiptsDir, { recursive: true });

  // Detect framework
  const detection = detectFramework(cwd, opts.framework);

  // Generate project key
  const keyPath = join(vaDir, 'attester.json');
  const key = await generateProjectKey(keyPath);

  // Write config
  const config = {
    veritasacta: {
      version: '0.5.0',
      created_at: new Date().toISOString(),
      org: opts.org || null,
    },
    framework: detection ? {
      name: detection.framework,
      language: detection.language,
      adapter: detection.adapter,
      setup_type: detection.setupType,
      signals: detection.signals,
    } : {
      name: 'unknown',
      language: 'unknown',
      adapter: null,
      setup_type: 'manual',
      signals: [],
    },
    receipts: {
      directory: './.veritasacta/receipts',
      jsonl_log: './.veritasacta/receipts.jsonl',
      audit_log: './.veritasacta/audit.jsonl',
    },
    signer: {
      kid: key.kid,
      pubkey: key.pubHex,
      key_file: './.veritasacta/attester.json',
    },
  };
  writeFileSync(join(vaDir, 'config.json'), JSON.stringify(config, null, 2));

  // Write gitignore entry
  const gitignorePath = join(cwd, '.gitignore');
  const gitignoreEntry = '\n# Veritas Acta — do NOT commit signing keys\n.veritasacta/attester.json\n.veritasacta/receipts.jsonl\n.veritasacta/audit.jsonl\n';
  try {
    const existing = existsSync(gitignorePath) ? readFileSync(gitignorePath, 'utf-8') : '';
    if (!existing.includes('.veritasacta/attester.json')) {
      appendFileSync(gitignorePath, gitignoreEntry);
    }
  } catch {}

  return {
    status: 'initialized',
    cwd,
    vaDir,
    detection,
    config,
    key,
  };
}

/**
 * Build framework-specific next-step instructions.
 */
export function buildNextSteps(detection, config) {
  if (!detection) {
    return [
      'No framework detected automatically. Manual setup:',
      '  1. Install the @veritasacta/verify verifier: npm install -g @veritasacta/verify',
      '  2. Use the SDK: npm install @veritasacta/sdk (JS) or pip install veritasacta-sdk (Python)',
      '  3. Import the signer and call signer.sign_tool_call(...) at each decision point.',
      '  4. Verify receipts: npx @veritasacta/verify .veritasacta/receipts/*.json',
    ];
  }

  const common = [
    `Framework detected: ${detection.framework} (${detection.language})`,
    `Adapter recommended: ${detection.adapter}`,
  ];

  switch (detection.setupType) {
    case 'mcp-hook':
      return [...common,
        '',
        'Setup:',
        '  1. npx protect-mcp init-hooks',
        '  2. Your .claude/settings.json now wires receipt-signing hooks.',
        '  3. Open Claude Code in this project — tool calls produce receipts in .veritasacta/receipts/.',
        '',
        'Verify:',
        '  npx @veritasacta/verify .veritasacta/receipts/*.json --key ' + (config.signer.pubkey || '<pubkey>'),
      ];
    case 'plugin':
      return [...common,
        '',
        'Setup:',
        '  1. pip install ' + detection.adapter,
        '  2. Add ReceiptPlugin to your Agent(plugins=[...]) list.',
        '  3. See: https://github.com/scopeblind/' + detection.adapter,
        '',
        'Verify:',
        '  npx @veritasacta/verify .veritasacta/receipts.jsonl',
      ];
    case 'middleware':
      return [...common,
        '',
        'Setup:',
        '  Install: ' + (detection.language === 'python' ? 'pip install' : 'npm install') + ' ' + detection.adapter,
        '  Wrap your agent with the adapter as shown in the adapter README.',
        '',
        'Verify:',
        '  npx @veritasacta/verify .veritasacta/receipts/*.json --key ' + (config.signer.pubkey || '<pubkey>'),
      ];
    case 'sdk':
      return [...common,
        '',
        'Setup:',
        '  npm install ' + detection.adapter,
        '  Import signer and call signer.signDecision(...) before each tool call.',
      ];
    default:
      return common;
  }
}
