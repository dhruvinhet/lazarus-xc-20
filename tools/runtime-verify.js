// Integrity gate for downloaded historical Node.js runtimes. A binary is NEVER extracted or executed unless its SHA-256
// matches an entry of the official checksum list for exactly that file name. Missing, malformed, or mismatching checksum
// information is a failure, and the caller must classify the historical reconstruction as unavailable (H3).
// Limit (documented, not hidden): the checksum list comes from the same origin (nodejs.org over TLS) as the archive. This guards
// against corruption and partial substitution, not against a compromised origin; the GPG-signed list is not verified here.
'use strict';
const crypto = require('crypto');
const cmp = (a, b) => { const x = a.split('.').map(Number), y = b.split('.').map(Number); for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i]; return 0; };
const sha = b => crypto.createHash('sha256').update(b).digest('hex');

// Strict parser: every non-empty line must be "<64 lowercase hex>  <file name>". Any other line makes the whole list untrusted.
function parseShasums(text) {
  const map = new Map(), bad = [];
  for (const raw of String(text == null ? '' : text).split(/\r?\n/)) {
    const line = raw.trim(); if (!line) continue;
    const m = line.match(/^([0-9a-f]{64}) {2}([A-Za-z0-9._\/-]+)$/);
    if (!m) { bad.push(line.slice(0, 60)); continue; }
    if (map.has(m[2]) && map.get(m[2]) !== m[1]) bad.push('conflicting entries for ' + m[2]);
    map.set(m[2], m[1]);
  }
  return { map, bad };
}
// -> { ok, expected, actual, outcome }
function verifyBuffer(file, buf, shasumsText) {
  const actual = sha(buf);
  if (shasumsText == null || !String(shasumsText).trim()) return { ok: false, expected: null, actual, outcome: 'failed: checksum list missing or empty' };
  const { map, bad } = parseShasums(shasumsText);
  if (bad.length) return { ok: false, expected: null, actual, outcome: 'failed: checksum list malformed (' + bad.length + ' bad line(s))' };
  if (!map.has(file)) return { ok: false, expected: null, actual, outcome: 'failed: no checksum listed for ' + file };
  const expected = map.get(file);
  if (expected !== actual) return { ok: false, expected, actual, outcome: 'failed: checksum mismatch' };
  return { ok: true, expected, actual, outcome: 'verified' };
}
// get(url) -> Promise<Buffer>; extract(buf, rec) -> Promise (called ONLY after verification). Returns the record to log.
async function acquireRuntime({ get, line, index, extract }) {
  const rec = { line, version: null, file: null, source: null, checksum_source: null, expected_sha256: null, actual_sha256: null, verification: 'not attempted', verified: false };
  const v = (index || []).map(e => String(e.version || '').slice(1)).filter(x => x.startsWith(line + '.')).sort(cmp).pop();
  if (!v) { rec.verification = 'failed: no release found for line ' + line; return rec; }
  rec.version = v; rec.file = `node-v${v}-linux-x64.tar.gz`;
  const base = `https://nodejs.org/dist/v${v}/`; rec.source = base + rec.file; rec.checksum_source = base + 'SHASUMS256.txt';
  let tgz; try { tgz = await get(rec.source); } catch (e) { rec.verification = 'failed: download: ' + e.message; return rec; }
  let sums = null; try { sums = (await get(rec.checksum_source)).toString(); } catch (e) { rec.verification = 'failed: checksum list unavailable: ' + e.message; rec.actual_sha256 = sha(tgz); return rec; }
  const r = verifyBuffer(rec.file, tgz, sums);
  rec.expected_sha256 = r.expected; rec.actual_sha256 = r.actual; rec.verification = r.outcome;
  if (!r.ok) return rec;
  try { await extract(tgz, rec); rec.verified = true; } catch (e) { rec.verification = 'failed: extract: ' + e.message; }
  return rec;
}
module.exports = { parseShasums, verifyBuffer, acquireRuntime, cmp };
