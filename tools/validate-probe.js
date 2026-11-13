// TRUSTED gate (P0-1 fix). Decides whether the trusted sandbox probe's report may ever be treated as security evidence.
// Runs on the HOST, after the probe container has exited and been removed. Never executes anything from either container.
//
// Why this exists: subject code and the trusted probe must never be able to influence each other's evidence. Earlier,
// both ran against the same writable /out mount, so subject code could pre-create a forged sandbox-probe.json (optionally
// made read-only) before the probe ran. tools/run-sandbox.sh now gives each role its own host-created directory that is
// never mounted into the other container, which already makes that specific race impossible. This tool adds the second,
// independent layer: even a report that genuinely came out of the probe's own directory is admitted as evidence only if
//   1. the HOST-recorded launch status (written by run-sandbox.sh, never inside any container) shows role=probe, a clean
//      exit code of exactly 0, and no timeout, and
//   2. the report file itself is a regular, single-link, size-bounded file (the same hardened reader used for untrusted
//      artifacts) whose JSON matches the expected schema (required fields, required types).
// Only then is the EXACT validated byte content copied into the meta/ directory, which the sanitizer and every v2.1
// checker treat as trusted. If anything above fails, sandbox-probe.json is never written to meta/ at all: every checker
// that depends on it (V2-sandbox-*) then correctly fails on "missing", and probe-admission.json (always written, admitted
// true or false) makes the reason auditable instead of ambiguous.
// usage: node validate-probe.js <probe-out dir> <launch-status file> <meta dir>
'use strict';
const fs = require('fs'), path = require('path');
const { readGuardedFile } = require('./sanitize-out.js');

function requireFields(o, spec, prefix) {
  const problems = [];
  for (const [k, type] of Object.entries(spec)) {
    if (!o || !(k in o)) { problems.push(prefix + k + ' missing'); continue; }
    const v = o[k];
    const ok = type === 'array' ? Array.isArray(v) : type === 'object' ? (v && typeof v === 'object' && !Array.isArray(v)) : typeof v === type;
    if (!ok) problems.push(prefix + k + ' has the wrong type (expected ' + type + ')');
  }
  return problems;
}
function validateSchema(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return ['document is not an object'];
  let problems = requireFields(doc, { v: 'number', node: 'string', ops: 'array', proc: 'object', env: 'object', mounts: 'array', repo_write: 'object' }, '');
  if (Array.isArray(doc.ops)) doc.ops.forEach((o, i) => { problems = problems.concat(requireFields(o, { op: 'string', target: 'string', attempted: 'boolean', result: 'string' }, 'ops[' + i + '].')); });
  if (doc.proc && typeof doc.proc === 'object') problems = problems.concat(requireFields(doc.proc, { uid: 'number', cap_eff: 'string', no_new_privs: 'string' }, 'proc.'));
  if (doc.env && typeof doc.env === 'object') problems = problems.concat(requireFields(doc.env, { names: 'array', token_like_count: 'number', canary_value_count: 'number', forbidden_names_present: 'array' }, 'env.'));
  if (doc.repo_write && typeof doc.repo_write === 'object') problems = problems.concat(requireFields(doc.repo_write, { attempted: 'string', http: 'string', result: 'string', target: 'string' }, 'repo_write.'));
  if (Array.isArray(doc.mounts)) doc.mounts.forEach((m, i) => { problems = problems.concat(requireFields(m, { mount_point: 'string', ro: 'boolean' }, 'mounts[' + i + '].')); });
  return problems;
}

// Pure decision function (no fs side effects besides the two files it is told to write), so tests can call it directly
// with constructed inputs, and so the real CLI path and the test path exercise identical logic.
function admit({ probeOutDir, statusFile, metaOutDir }) {
  fs.mkdirSync(metaOutDir, { recursive: true });
  const rec = { v: 1, admitted: false, reason: null, exit_code: null, timed_out: null, checked_at: new Date().toISOString() };
  const finish = reason => {
    rec.reason = reason;
    // 'wx' (exclusive create): this gate decides at most once per job. If probe-admission.json already exists, a second
    // call never overwrites it and never silently re-admits; it fails closed and says so, instead of crashing the workflow.
    try { fs.writeFileSync(path.join(metaOutDir, 'probe-admission.json'), JSON.stringify(rec, null, 1), { flag: 'wx' }); }
    catch (e) { rec.admitted = false; rec.reason = 'admission record already exists for this job (refusing to decide twice): ' + (e.code || e.message); }
    return rec;
  };

  // 1. host-recorded launch status: written by run-sandbox.sh from OUTSIDE every container. Neither the subject
  // container nor the probe container ever has this path mounted, so neither can forge or suppress it.
  let st, statusErr;
  try { st = JSON.parse(fs.readFileSync(statusFile, 'utf8')); }
  catch (e) { statusErr = e.code === 'ENOENT' ? 'missing' : `unreadable or invalid (${e.code || e.message})`; return finish(`launch status file ${statusErr}: ${statusFile}`); }
  rec.exit_code = typeof st.exit_code === 'number' ? st.exit_code : null;
  rec.timed_out = st.timed_out === true;
  if (st.role !== 'probe') return finish('launch status does not record role=probe (got ' + JSON.stringify(st.role) + ')');
  // run-sandbox.sh could not hand probe-out/ back to this (the host's) identity after the container exited. Treated as
  // its own, explicit, distinct failure reason - never silently folded into a generic read error below.
  if (st.handback_failed === true) return finish('run-sandbox.sh could not hand probe-out/ back to the host identity after the probe container exited (handback_failed)');
  if (rec.timed_out) return finish('probe container timed out');
  if (rec.exit_code !== 0) return finish('probe container exited ' + JSON.stringify(st.exit_code) + ' (required exactly 0)');

  // 2. the probe's own report, read with the same hardened, symlink/hardlink/size-safe reader used for untrusted artifacts
  // (defense in depth: even though nothing else can reach probe-out/, the report is still treated as unverified until here).
  // The reader distinguishes a genuinely missing file ("vanished") from a real permission problem (e.g. "cannot stat
  // (EACCES)", which previously surfaced here as the misleading "vanished" too, hiding a real handoff/permission bug.
  const r = readGuardedFile(probeOutDir, 'sandbox-probe.json', 'json');
  if (r.err) return finish('sandbox-probe.json: ' + r.err);
  let doc; try { doc = JSON.parse(r.data.toString('utf8')); } catch (e) { return finish('sandbox-probe.json is not valid JSON'); }
  const problems = validateSchema(doc);
  if (problems.length) return finish('schema: ' + problems.slice(0, 6).join('; '));

  // 3. admit: publish the EXACT validated bytes (never a re-serialization), so the sanitizer's recorded SHA-256 always
  // matches what was actually checked here, and so nothing downstream can introduce a discrepancy.
  try { fs.writeFileSync(path.join(metaOutDir, 'sandbox-probe.json'), r.data, { flag: 'wx' }); } catch (e) { return finish('could not publish the validated report: ' + (e.code || e.message)); }
  rec.admitted = true;
  return finish('ok');
}

module.exports = { admit, validateSchema, requireFields };
if (require.main === module) {
  const [probeOutDir, statusFile, metaOutDir] = process.argv.slice(2);
  if (!probeOutDir || !statusFile || !metaOutDir) { console.error('usage: validate-probe.js <probe-out dir> <launch-status file> <meta dir>'); process.exit(2); }
  const rec = admit({ probeOutDir, statusFile, metaOutDir });
  console.log('PROBE-ADMISSION admitted=' + rec.admitted + ' reason=' + rec.reason);
  process.exit(0); // an evaluation tool only: it never aborts the workflow. The ABSENCE of meta/sandbox-probe.json, and
                    // probe-admission.json's content, are what every V2-sandbox-* and V2-probe-admitted check act on.
}
