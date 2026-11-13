// TRUSTED tool. Treats everything the container wrote as untrusted DATA: it is never executed, imported, or printed.
// Two modes:
//   node sanitize-out.js sanitize --in <out> --meta <meta> --out <clean>   (examine job, after the container has exited)
//   node sanitize-out.js verify   --dir <downloaded artifact dir>           (deliver job, before anything is published)
//
// Threats handled (fail closed: anything doubtful is dropped and recorded, never copied):
//   - symbolic links, directories, FIFOs, sockets, devices      -> only regular files are taken (lstat, then fstat on the opened descriptor)
//   - hard links                                                -> nlink must be 1
//   - path tricks / unexpected names                            -> strict allowlist of exact names; no subdirectories at all
//   - oversized files, many files                               -> per-kind size caps, entry cap, total cap
//   - content changing after validation                         -> bytes are read ONCE from the opened descriptor into memory and the copy is
//                                                                  written to a separate directory; the original is never used again
//   - hostile file names in logs/reports                        -> names are escaped before they are stored or printed
//   - malformed JSON presented as data                          -> JSON files must parse (parsing only; nothing is evaluated)
// The sanitized directory carries sanitize-report.json with the SHA-256 of every file, so later jobs can detect tampering.
'use strict';
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const C = fs.constants;
const LIMITS = { maxEntries: 64, jsonMax: 512 * 1024, logMax: 1024 * 1024, textMax: 4 * 1024, totalMax: 4 * 1024 * 1024, reportMax: 256 * 1024 };
// Files the SUBJECT CONTAINER may produce (written under /out, the only mount it can write to). This list must NEVER
// include sandbox-probe.json or probe-admission.json: those are security-isolation evidence and must be structurally
// impossible for subject code to forge. See P0-1 fix below and workbench/tools/validate-probe.js.
const OUT_RULES = [
  [/^historical\.json$/, 'json'], [/^baseline-passing-tests\.json$/, 'json'],
  [/^(install-locked|install-asof|today-install|today-test)\.log$/, 'log'], [/^historical-(test|mocha-json)-[12]\.log$/, 'log'],
];
// Files written by TRUSTED host commands or admitted by a trusted tool, into a directory NEVER mounted into any
// container that runs subject code. sandbox-probe.json is admitted here only by validate-probe.js, and only after it
// confirms (from a host-recorded exit status, outside every container) that the trusted probe container itself ran
// to completion, and that the JSON matches the expected schema. probe-admission.json is validate-probe.js's own record
// of that decision, written unconditionally (admitted true or false) so an absent sandbox-probe.json is never silently
// ambiguous between "probe not requested" and "probe ran but was rejected".
const META_RULES = [
  [/^node-image\.txt$/, 'text'], [/^node-image-digest\.txt$/, 'text'], [/^docker-version\.txt$/, 'text'],
  [/^container\.log$/, 'log'], [/^probe-container\.log$/, 'log'],
  [/^sandbox-probe\.json$/, 'json'], [/^probe-admission\.json$/, 'json'],
];
const kindOf = (name, rules) => { for (const [re, k] of rules) if (re.test(name)) return k; return null; };
const nameKind = name => kindOf(name, OUT_RULES) || kindOf(name, META_RULES);
const esc = s => String(s).replace(/[^A-Za-z0-9._-]/g, '?').slice(0, 64);
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const capOf = kind => kind === 'json' ? LIMITS.jsonMax : kind === 'log' ? LIMITS.logMax : LIMITS.textMax;

// Read one entry safely. Returns { data, truncated } or { err }.
function take(dir, name, kind, slack = 0) {
  const p = path.join(dir, name); let l;
  // ENOENT (the file genuinely does not exist) is reported as "vanished". Anything else - EACCES/EPERM (the file may
  // well exist, but this process cannot even stat it, typically because a containing directory denies traversal to
  // it), or any other errno - is reported with its real code, never collapsed into "vanished": those are different
  // failures with different causes, and conflating them previously made a real permission problem on the probe's
  // output directory read back as if the report had simply never been written.
  try { l = fs.lstatSync(p); } catch (e) { return { err: e.code === 'ENOENT' ? 'vanished' : `cannot stat (${e.code || e.message})` }; }
  if (!l.isFile()) return { err: 'not a regular file (' + (l.isSymbolicLink() ? 'symlink' : l.isDirectory() ? 'directory' : 'special') + ')' };
  let fd;
  try { fd = fs.openSync(p, C.O_RDONLY | (C.O_NOFOLLOW || 0) | (C.O_NONBLOCK || 0)); } catch (e) { return { err: 'open failed: ' + (e.code || 'error') }; }
  try {
    const s = fs.fstatSync(fd);
    if (!s.isFile()) return { err: 'not a regular file (after open)' };
    if (s.nlink !== 1) return { err: 'hard link (nlink=' + s.nlink + ')' };
    if (l.ino && s.ino && (l.ino !== s.ino || l.dev !== s.dev)) return { err: 'replaced between check and open' };
    const cap = capOf(kind) + slack, buf = Buffer.alloc(cap + 1); let n = 0;
    while (n < buf.length) { const r = fs.readSync(fd, buf, n, buf.length - n, null); if (r === 0) break; n += r; } // never trust s.size: the file may grow
    if (n > cap) { if (kind === 'log') return { data: Buffer.concat([buf.subarray(0, cap), Buffer.from('\n[sanitizer: truncated at ' + cap + ' bytes]\n')]), truncated: true }; return { err: 'too large (over ' + cap + ' bytes)' }; }
    const data = Buffer.from(buf.subarray(0, n));
    if (kind === 'json') { try { JSON.parse(data.toString('utf8')); } catch (e) { return { err: 'not valid JSON' }; } }
    return { data, truncated: false };
  } finally { fs.closeSync(fd); }
}

function sanitize({ inDir, metaDir, outDir }) {
  const rep = { v: 1, status: 'ok', limits: LIMITS, accepted: [], rejected: [] };
  fs.mkdirSync(outDir, { recursive: true });
  let total = 0;
  const reject = (name, reason) => rep.rejected.push({ name: esc(name), reason });
  const accept = (dir, name, kind, source) => {
    const r = take(dir, name, kind); if (r.err) return reject(name, r.err);
    if (total + r.data.length > LIMITS.totalMax) return reject(name, 'total size limit reached');
    // 'wx' (exclusive create) means a later source can NEVER silently overwrite an earlier one for the same name: if a name were
    // ever mistakenly allowed from both buckets, the second write fails closed as a rejection instead of winning a race.
    try { fs.writeFileSync(path.join(outDir, name), r.data, { flag: 'wx', mode: 0o644 }); } catch (e) { return reject(name, 'write failed: ' + (e.code || 'error')); }
    total += r.data.length; rep.accepted.push({ name, bytes: r.data.length, sha256: sha(r.data), truncated: r.truncated, source });
  };
  // 1. host-only trusted files (names are fixed; a missing file is simply not accepted). Processed FIRST, so that if a name
  // were ever mistakenly duplicated into OUT_RULES, the trusted copy wins the 'wx' race and the subject's copy is rejected.
  let metaNames = []; try { metaNames = fs.readdirSync(metaDir); } catch (e) { }
  for (const n of metaNames.sort()) { const k = kindOf(n, META_RULES); if (k) accept(metaDir, n, k, 'meta'); else reject(n, 'name not allowed (meta)'); }
  // 2. subject container output: names are allowlisted exactly; anything else is dropped and recorded
  let names = []; try { names = fs.readdirSync(inDir); } catch (e) { rep.status = 'error'; reject('(output directory)', 'unreadable'); }
  if (names.length > LIMITS.maxEntries) { rep.status = 'limit-exceeded'; reject('(many entries)', 'more than ' + LIMITS.maxEntries + ' entries; container output ignored'); names = []; }
  for (const n of names.sort()) { const k = kindOf(n, OUT_RULES); if (!k) { reject(n, 'name not allowed'); continue; } accept(inDir, n, k, 'out'); }
  if (rep.rejected.length && rep.status === 'ok') rep.status = 'rejections';
  fs.writeFileSync(path.join(outDir, 'sanitize-report.json'), JSON.stringify(rep, null, 1), { flag: 'wx', mode: 0o644 });
  return rep;
}

// Integrity check of an artifact directory before delivery. Returns { ok, problems }.
function verify(dir) {
  const problems = []; let names;
  try { names = fs.readdirSync(dir); } catch (e) { return { ok: false, problems: ['directory unreadable'] }; }
  if (names.length > LIMITS.maxEntries + 2) problems.push('too many entries');
  let rep = null;
  if (!names.includes('sanitize-report.json')) problems.push('sanitize-report.json missing');
  else { const r = take(dir, 'sanitize-report.json', 'json'); if (r.err) problems.push('report: ' + r.err); else if (r.data.length > LIMITS.reportMax) problems.push('report too large'); else rep = JSON.parse(r.data.toString('utf8')); }
  if (!rep || !Array.isArray(rep.accepted)) { problems.push('report has no accepted list'); return { ok: false, problems }; }
  const listed = new Map(rep.accepted.map(a => [a && a.name, a]));
  let total = 0;
  for (const n of names) {
    if (n === 'sanitize-report.json') continue;
    const k = nameKind(n); const a = listed.get(n);
    if (!k) { problems.push('unexpected name ' + esc(n)); continue; }
    if (!a) { problems.push('file not in report: ' + esc(n)); continue; }
    const r = take(dir, n, k, 64); if (r.err) { problems.push(esc(n) + ': ' + r.err); continue; }
    total += r.data.length;
    if (!r.truncated && (sha(r.data) !== a.sha256 || r.data.length !== a.bytes)) problems.push(esc(n) + ': content differs from the report');
    if (r.truncated) problems.push(esc(n) + ': larger than the sanitizer cap');
  }
  for (const a of rep.accepted) if (!names.includes(a.name)) problems.push('reported file missing: ' + esc(a.name));
  if (total > LIMITS.totalMax) problems.push('total size over limit');
  return { ok: problems.length === 0, problems };
}

module.exports = { LIMITS, OUT_RULES, META_RULES, nameKind, sanitize, verify, esc, readGuardedFile: take };
if (require.main === module) {
  const a = process.argv.slice(2), mode = a[0], opt = k => { const i = a.indexOf('--' + k); return i > 0 ? a[i + 1] : null; };
  try {
    if (mode === 'sanitize') {
      const o = opt('out'); if (!opt('in') || !o) throw new Error('usage: sanitize --in <dir> --meta <dir> --out <dir>');
      const r = sanitize({ inDir: opt('in'), metaDir: opt('meta') || '/nonexistent', outDir: o });
      console.log(`sanitize: status=${r.status} accepted=${r.accepted.length} rejected=${r.rejected.length}`);
      for (const x of r.rejected) console.log(`  rejected ${x.name}: ${x.reason}`);
      process.exit(0);
    } else if (mode === 'verify') {
      const r = verify(opt('dir') || ''); console.log(r.ok ? 'verify: ok' : 'verify: FAILED'); for (const p of r.problems) console.log('  ' + p); process.exit(r.ok ? 0 : 1);
    } else throw new Error('mode must be sanitize or verify');
  } catch (e) { console.error('sanitize-out: ' + e.message); process.exit(2); } // fail closed
}
