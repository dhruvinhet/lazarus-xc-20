// TRUSTED measurement tool. Runs INSIDE the restricted container (started by run-sandbox.sh, same flags as project code) and
// performs real attempts at things the container must not be able to do. Every operation is attempted and its outcome recorded;
// a skipped operation is recorded as such and is a FAIL for the checker. It prints no environment VALUES and reads no credential.
// Output: /out/sandbox-probe.json. It never touches the host runner: it cannot, and it does not try to leave the container.
'use strict';
const fs = require('fs'), net = require('net'), https = require('https');
const CANARY = 'CANARY-not-a-real-key-7f3a';
const TOKENISH = /(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})/;
const R = { v: 1, node: process.version, ops: [] };
const record = (op, target, result, code) => R.ops.push({ op, target, attempted: true, result, code: code || null });
const classify = e => (['ENOENT', 'ENOTDIR'].includes(e.code) ? 'absent' : 'denied');
function tryWrite(op, file) { try { fs.writeFileSync(file, 'x', { flag: 'wx' }); try { fs.unlinkSync(file); } catch (e) { } record(op, file, 'SUCCEEDED'); } catch (e) { record(op, file, classify(e), e.code); } }
function tryList(op, dir) { try { const n = fs.readdirSync(dir).length; record(op, dir, 'SUCCEEDED', 'entries=' + n); } catch (e) { record(op, dir, classify(e), e.code); } }
function tryConnect(op, sock) { return new Promise(ok => { let done = false; const fin = (r, c) => { if (done) return; done = true; record(op, sock, r, c); ok(); };
  const s = net.connect({ path: sock }); s.setTimeout(3000, () => { s.destroy(); fin('denied', 'timeout'); });
  s.on('connect', () => { s.destroy(); fin('SUCCEEDED'); }); s.on('error', e => fin(classify(e), e.code)); }); }

// 1. writes that must be refused: read-only mounts and the file system root
tryWrite('write-snap', '/snap/probe-write.txt');
tryWrite('write-tools', '/tools/probe-write.txt');
tryWrite('write-root', '/probe-write.txt');
// 2. host locations that must not exist inside the container
tryList('read-home-runner', '/home/runner');
tryList('read-github', '/github');
tryList('read-runner-work', '/home/runner/work');
// 3. identity and privileges
const status = (() => { try { return fs.readFileSync('/proc/self/status', 'utf8'); } catch (e) { return ''; } })();
const field = k => { const m = status.match(new RegExp('^' + k + ':\\s*(\\S+)', 'm')); return m ? m[1] : null; };
R.proc = { uid: field('Uid') === null ? null : Number(field('Uid')), gid: field('Gid') === null ? null : Number(field('Gid')), cap_eff: field('CapEff'), cap_bnd: field('CapBnd'), no_new_privs: field('NoNewPrivs'), seccomp: field('Seccomp') };
// 4. environment: names and counts only, never values
const names = Object.keys(process.env).sort(); let tokenLike = 0, canaryVal = 0;
for (const n of names) { const v = process.env[n] || ''; if (TOKENISH.test(v)) tokenLike++; if (v.includes(CANARY)) canaryVal++; }
const FORBIDDEN = /^(ACTIONS_ID_TOKEN_REQUEST_(URL|TOKEN)|ACTIONS_RUNTIME_(TOKEN|URL)|ACTIONS_CACHE_URL|ACTIONS_RESULTS_URL|GITHUB_TOKEN|GH_TOKEN|GITHUB_ENV|GITHUB_OUTPUT|GITHUB_PATH|GITHUB_STEP_SUMMARY|LAZARUS_.*|.*_API_KEY|.*SECRET.*|.*PASSWORD.*)$/i;
R.env = { names, token_like_count: tokenLike, canary_value_count: canaryVal, forbidden_names_present: names.filter(n => FORBIDDEN.test(n)) };
// 5. mounts: what the container can actually see
try { R.mounts = fs.readFileSync('/proc/self/mountinfo', 'utf8').split('\n').filter(Boolean).map(l => { const f = l.split(' '); const dash = f.indexOf('-');
  return { mount_point: f[4], root: f[3], options: f[5], ro: String(f[5] || '').split(',').includes('ro'), fstype: f[dash + 1] || null }; }); } catch (e) { R.mounts = null; }
(async () => {
  await tryConnect('docker-socket-var-run', '/var/run/docker.sock');
  await tryConnect('docker-socket-run', '/run/docker.sock');
  // 6. a real, anonymous write attempt against the repository (no credential exists in this container, by design)
  const repo = process.env.GITHUB_REPOSITORY;
  R.repo_write = await new Promise(ok => {
    if (!repo) return ok({ attempted: 'no', http: 'none', result: 'not-attempted', target: 'none' });
    const body = JSON.stringify({ message: 'probe write', content: Buffer.from('probe').toString('base64') }); let done = false;
    const fin = (http, result) => { if (done) return; done = true; ok({ attempted: 'yes', http: String(http), result, target: repo, token_used: 'no' }); };
    const req = https.request({ host: 'api.github.com', method: 'PUT', path: '/repos/' + repo + '/contents/PROBE_WROTE_HERE.txt',
      headers: { 'User-Agent': 'lazarus-sandbox-probe', 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } },
      res => { fin(res.statusCode, res.statusCode >= 200 && res.statusCode < 300 ? 'SUCCEEDED' : 'denied'); res.resume(); });
    req.on('error', e => fin('none', 'no-response(' + (e.code || 'error') + ')')); req.setTimeout(15000, () => { fin('none', 'no-response(timeout)'); req.destroy(); }); req.end(body);
  });
  fs.writeFileSync('/out/sandbox-probe.json', JSON.stringify(R, null, 1));
  console.log('SANDBOX-PROBE written ops=' + R.ops.length);
})().catch(e => { try { R.error = String(e && e.message); fs.writeFileSync('/out/sandbox-probe.json', JSON.stringify(R, null, 1)); } catch (x) { } process.exit(1); });
