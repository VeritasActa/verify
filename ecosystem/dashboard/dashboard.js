/**
 * Veritas Acta audit dashboard scaffold.
 *
 * Purpose: render the output of `npx @veritasacta/verify --json` or a
 * directory of receipts, in-browser, fully offline. No network, no
 * telemetry, no server — this is a single static file you can drop on
 * any host (GitHub Pages, Cloudflare Pages, a local file://, …).
 *
 * Verification here is structural (canonical hash + chain linkage)
 * because browsers don't ship Ed25519 key parsers for arbitrary hex
 * identifiers. For cryptographic verification, users paste the output
 * of the real verifier's --json mode and we render the already-verified
 * results.
 */

const dz = document.getElementById('dz');
const fileInput = document.getElementById('fileInput');
const paste = document.getElementById('jsonPaste');
const summary = document.getElementById('summary');
const table = document.getElementById('table');
const tbody = document.getElementById('tableBody');
const empty = document.getElementById('empty');
const viewToggle = document.getElementById('viewToggle');
const legend = document.getElementById('legend');
const graphEl = document.getElementById('graph');

let currentRows = [];  // cached for view switches
let currentView = 'table';

// ───── Canonical JSON (JCS, RFC 8785) minimal port ─────

function jcs(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs(value[k])}`).join(',')}}`;
}

async function sha256b64url(str) {
  const enc = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest('SHA-256', enc);
  const bytes = new Uint8Array(hash);
  let b64 = btoa(String.fromCharCode(...bytes));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ───── State + rendering ─────

async function ingestReceipts(receipts) {
  // Receipts: [{ payload, signature }, ...] — sort by issued_at, compute hashes, detect chain.
  const decorated = [];
  for (const r of receipts) {
    const issued = (r.payload && r.payload.issued_at) || '';
    const hash = await sha256b64url(jcs(r));
    decorated.push({
      raw: r,
      issued_at: issued,
      action: (r.payload && (r.payload.action || r.payload.tool_name)) || '(unknown)',
      decision: (r.payload && r.payload.decision) || '(unset)',
      kid: (r.signature && r.signature.kid) || '(unset)',
      hash,
      previousHash: (r.payload && r.payload.previousReceiptHash) || null,
      // AIP-0001 extensions (v0.5.3): trace_id, parent_receipt_id
      trace_id: (r.payload && r.payload.trace_id) || null,
      parent_receipt_id: (r.payload && r.payload.parent_receipt_id) || null,
    });
  }
  decorated.sort((a, b) => (a.issued_at < b.issued_at ? -1 : a.issued_at > b.issued_at ? 1 : 0));

  // Build hash index for chain integrity check.
  const hashIndex = new Map(decorated.map((d) => [d.hash, d]));
  let broken = 0;
  for (const d of decorated) {
    if (d.previousHash && !hashIndex.has(d.previousHash)) {
      d.chainBreak = true;
      broken++;
    }
  }

  currentRows = decorated;
  render(decorated, { broken });
}

function render(rows, stats) {
  if (rows.length === 0) {
    empty.style.display = 'block';
    summary.style.display = 'none';
    table.style.display = 'none';
    viewToggle.style.display = 'none';
    legend.style.display = 'none';
    graphEl.style.display = 'none';
    return;
  }
  empty.style.display = 'none';
  summary.style.display = 'grid';
  viewToggle.style.display = 'inline-flex';

  const valid = rows.filter((r) => !r.chainBreak).length;
  const invalid = rows.length - valid;

  document.getElementById('stat-total').textContent = rows.length;
  document.getElementById('stat-valid').textContent = valid;
  document.getElementById('stat-invalid').textContent = invalid;
  document.getElementById('stat-broken').textContent = stats.broken;
  document.getElementById('stat-first').textContent = rows[0].issued_at || '(unknown)';
  document.getElementById('stat-last').textContent  = rows[rows.length - 1].issued_at || '(unknown)';

  // Table always keeps its content fresh even if hidden.
  tbody.replaceChildren(...rows.map((r) => {
    const tr = document.createElement('tr');
    const traceCell = r.trace_id
      ? `<span class="hash">${escapeHtml(r.trace_id.slice(0, 10))}…</span>`
      : '<span style="color: var(--muted)">—</span>';
    tr.innerHTML = `
      <td>${escapeHtml(r.issued_at)}</td>
      <td>${escapeHtml(r.action)}</td>
      <td class="status-cell">${escapeHtml(r.decision)}</td>
      <td class="hash">${escapeHtml(r.hash.slice(0, 12))}…</td>
      <td class="hash">${escapeHtml(r.kid)}</td>
      <td>${traceCell}</td>
      <td>${r.chainBreak
          ? '<span class="status invalid">chain break</span>'
          : '<span class="status valid">ok</span>'}</td>
    `;
    return tr;
  }));

  renderCurrentView();
}

function renderCurrentView() {
  if (currentView === 'table') {
    table.style.display = 'table';
    graphEl.style.display = 'none';
    legend.style.display = 'none';
  } else {
    table.style.display = 'none';
    graphEl.style.display = 'block';
    legend.style.display = 'flex';
    renderDag(currentRows);
  }
}

// ───── DAG renderer ─────

function renderDag(rows) {
  // Clear any previous render.
  graphEl.innerHTML = '';
  if (rows.length === 0) return;

  const W = graphEl.clientWidth || 800;
  const H = graphEl.clientHeight || 480;

  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  graphEl.appendChild(svg);

  // Simple force-style layout: index nodes by hash, place in a spiral
  // sorted by trace_id then issued_at.
  const byHash = new Map();
  for (const r of rows) byHash.set(r.hash, r);

  const traces = new Map();
  for (const r of rows) {
    const t = r.trace_id || '(no-trace)';
    if (!traces.has(t)) traces.set(t, []);
    traces.get(t).push(r);
  }

  // Layout: one column per trace, receipts stacked by issued_at within.
  const traceKeys = [...traces.keys()];
  const colW = W / (traceKeys.length + 1);

  const nodePositions = new Map();
  traceKeys.forEach((t, ti) => {
    const arr = traces.get(t);
    const rowH = Math.max(H / (arr.length + 1), 40);
    arr.forEach((r, ri) => {
      nodePositions.set(r.hash, {
        x: colW * (ti + 1),
        y: rowH * (ri + 1),
      });
    });
  });

  // Draw edges first (so nodes render on top).
  for (const r of rows) {
    if (r.previousHash) {
      const from = nodePositions.get(r.hash);
      const to = nodePositions.get(r.previousHash);
      if (from && to) {
        svg.appendChild(mkEdge(from, to, r.chainBreak ? 'edge-break' : 'edge-chain'));
      }
    }
    if (r.parent_receipt_id && r.parent_receipt_id !== r.previousHash) {
      const from = nodePositions.get(r.hash);
      const to = nodePositions.get(r.parent_receipt_id);
      if (from && to) {
        svg.appendChild(mkEdge(from, to, 'edge-parent'));
      }
    }
  }

  // Draw nodes.
  for (const r of rows) {
    const p = nodePositions.get(r.hash);
    if (!p) continue;
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.setAttribute('transform', `translate(${p.x}, ${p.y})`);

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('r', '10');
    circle.setAttribute('class', r.chainBreak ? 'node-circle break' : 'node-circle');
    g.appendChild(circle);

    const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    label.setAttribute('x', 14);
    label.setAttribute('y', 4);
    label.setAttribute('class', 'node-label');
    label.textContent = `${r.action} · ${r.hash.slice(0, 6)}`;
    g.appendChild(label);

    const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
    title.textContent = `action=${r.action}\nhash=${r.hash}\nissued_at=${r.issued_at}\ntrace=${r.trace_id || '(none)'}`;
    g.appendChild(title);

    svg.appendChild(g);
  }
}

function mkEdge(from, to, cls) {
  const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
  line.setAttribute('x1', from.x);
  line.setAttribute('y1', from.y);
  line.setAttribute('x2', to.x);
  line.setAttribute('y2', to.y);
  line.setAttribute('class', cls);
  line.setAttribute('stroke-width', '2');
  return line;
}

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ───── Input wiring ─────

async function handleFiles(fileList) {
  const receipts = [];
  for (const f of fileList) {
    const text = await f.text();
    try {
      const parsed = JSON.parse(text);
      if (Array.isArray(parsed)) {
        for (const r of parsed) if (r && r.payload && r.signature) receipts.push(r);
      } else if (parsed && parsed.payload && parsed.signature) {
        receipts.push(parsed);
      }
    } catch {
      /* skip */
    }
  }
  await ingestReceipts(receipts);
}

// View toggle buttons
for (const btn of document.querySelectorAll('.view-toggle button')) {
  btn.addEventListener('click', () => {
    currentView = btn.dataset.view;
    for (const b of document.querySelectorAll('.view-toggle button')) {
      b.classList.toggle('active', b === btn);
    }
    renderCurrentView();
  });
}

dz.addEventListener('click', () => fileInput.click());
dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('dragover'); });
dz.addEventListener('dragleave', () => dz.classList.remove('dragover'));
dz.addEventListener('drop', (e) => {
  e.preventDefault();
  dz.classList.remove('dragover');
  handleFiles(e.dataTransfer.files);
});
fileInput.addEventListener('change', (e) => handleFiles(e.target.files));

paste.addEventListener('input', () => {
  const text = paste.value.trim();
  if (!text) return;
  try {
    const parsed = JSON.parse(text);
    // Accept either a raw array, a single receipt, or verify --json output.
    const receipts = [];
    if (Array.isArray(parsed)) {
      receipts.push(...parsed.filter((r) => r.payload && r.signature));
    } else if (parsed.receipts) {
      receipts.push(...(parsed.receipts || []));
    } else if (parsed.payload && parsed.signature) {
      receipts.push(parsed);
    } else if (parsed.nodes) {
      // `verify chain explore --json` output shape.
      for (const n of parsed.nodes) {
        receipts.push({
          payload: {
            issued_at: n.issued_at,
            action: n.action,
            previousReceiptHash: n.previousHash || undefined,
          },
          signature: { kid: n.kid, alg: 'ed25519', sig: '' },
        });
      }
    }
    ingestReceipts(receipts);
  } catch {
    /* ignore — user still typing */
  }
});
