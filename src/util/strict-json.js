/** Reject ambiguous JSON before JSON.parse can discard duplicate members. */
export function parseReceiptJson(text, { maxBytes = 1024 * 1024, maxDepth = 64 } = {}) {
  const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
  if (typeof text !== 'string') fail('malformed_json', 'Expected JSON text.');
  if (new TextEncoder().encode(text).length > maxBytes) fail('input_too_large', `Input exceeds ${maxBytes} bytes.`);
  let i = 0;
  const ws = () => { while (/[\x20\t\r\n]/.test(text[i] || '\0')) i++; };
  const string = () => {
    const start = i++;
    while (i < text.length) {
      if (text[i] === '\\') { i += 2; continue; }
      if (text[i++] === '"') return JSON.parse(text.slice(start, i));
    }
    fail('malformed_json', 'Unterminated JSON string.');
  };
  const value = (depth) => {
    if (depth > maxDepth) fail('input_too_deep', 'JSON nesting limit exceeded.');
    ws();
    if (text[i] === '"') { string(); return; }
    if (text[i] === '{' || text[i] === '[') {
      const object = text[i++] === '{', end = object ? '}' : ']', keys = new Set();
      ws();
      if (text[i] === end) { i++; return; }
      for (;;) {
        ws();
        if (object) {
          if (text[i] !== '"') fail('malformed_json', 'Expected a JSON member name.');
          const key = string();
          if (keys.has(key)) fail('duplicate_key', `Duplicate JSON member: ${key}`);
          keys.add(key); ws();
          if (text[i++] !== ':') fail('malformed_json', 'Expected a colon.');
        }
        value(depth + 1); ws();
        if (text[i] === end) { i++; return; }
        if (text[i++] !== ',') fail('malformed_json', 'Expected a comma or closing delimiter.');
      }
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i));
    if (!token) fail('malformed_json', 'Expected a JSON value.');
    i += token[0].length;
  };
  try {
    value(0); ws();
    if (i !== text.length) fail('malformed_json', 'Unexpected content after JSON.');
    return JSON.parse(text);
  } catch (error) {
    if (!error.code) error.code = 'malformed_json';
    throw error;
  }
}

/**
 * Parse any other JSON a verification reads (a file beside the input, a line of a chain, a key set, a label map) as
 * the main input is read: duplicate members refused, with the CLI's limits. JSON.parse keeps the last of two members
 * that share a name and another parser may keep the first, so a duplicate could read one way here and another way
 * elsewhere. Before, these were read with JSON.parse, so a receipt refused as the main input verified on
 * --replay-chain. Throws as parseReceiptJson does.
 */
export function parseJsonStrict(text) {
  return parseReceiptJson(text, { maxBytes: 50 * 1024 * 1024, maxDepth: 128 });
}
