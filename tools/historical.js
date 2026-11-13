// Runs INSIDE the container, as an unprivileged user, next to untrusted project code. Holds no credentials.
// Measures: can the project be installed and its tests run in the runtime it was written for (level H1/H2/H3),
// and does it fail on the current runtime today. Writes /out/historical.json and raw logs.
const fs = require('fs'), path = require('path'), cp = require('child_process'), https = require('https'), crypto = require('crypto');
const OUT = '/out', WORK = '/tmp/work', TODAY = '/tmp/today', OLD = '/tmp/oldnode';
const TARGET_MAJOR = 26; // Node.js 26 'Lithium': Active LTS since 2026-10-28 per the Node.js release schedule
const R = { v: 1, started: new Date().toISOString(), target_runtime: process.version, target_major_expected: TARGET_MAJOR, target_is_expected: Number(process.versions.node.split('.')[0]) === TARGET_MAJOR, steps: [] };
const PUBLIC = process.env.GITHUB_REPOSITORY ? { GITHUB_REPOSITORY: process.env.GITHUB_REPOSITORY } : {};
const save = () => fs.writeFileSync(path.join(OUT, 'historical.json'), JSON.stringify(R, null, 1));
const sh = (name, cmd, opts = {}) => { const t0 = Date.now(); const r = cp.spawnSync('sh', ['-c', cmd], { cwd: opts.cwd || WORK, env: opts.env || process.env, timeout: opts.timeout || 600000, maxBuffer: 64 << 20, encoding: 'utf8' });
  const log = `$ ${cmd}\n[exit ${r.status} signal ${r.signal || ''} ${Date.now() - t0}ms]\n--- stdout\n${r.stdout || ''}\n--- stderr\n${r.stderr || ''}\n`;
  fs.writeFileSync(path.join(OUT, name + '.log'), log.slice(0, 2 << 20)); R.steps.push({ name, exit: r.status, ms: Date.now() - t0 }); save(); return r; };
const get = (url, n = 0) => new Promise((ok, no) => https.get(url, { headers: { 'User-Agent': 'lazarus-xc' } }, res => {
  if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && n < 5) return ok(get(res.headers.location, n + 1));
  if (res.statusCode !== 200) return no(new Error('HTTP ' + res.statusCode + ' ' + url)); const b = []; res.on('data', d => b.push(d)); res.on('end', () => ok(Buffer.concat(b))); }).on('error', no));
const { acquireRuntime } = require('/tools/runtime-verify.js');
const mochaResults = text => { const i = text.lastIndexOf('{\n  "stats"'); if (i < 0) return null; try { const j = JSON.parse(text.slice(i)); return { passes: j.passes.map(t => t.fullTitle), failures: j.failures.map(t => t.fullTitle) }; } catch (e) { return null; } };
(async () => {
  fs.mkdirSync('/tmp/home', { recursive: true });
  cp.execSync(`cp -a /snap/subject ${WORK}`);
  const src = JSON.parse(fs.readFileSync('/snap/SOURCE.json', 'utf8')); R.source = src;
  let pkg; try { pkg = JSON.parse(fs.readFileSync(path.join(WORK, 'package.json'), 'utf8')); } catch (e) { R.level = 'H3'; R.reason = 'no readable package.json'; return save(); }
  const testScript = (pkg.scripts || {}).test || ''; R.test_script = testScript;
  // 1. choose and fetch the historical runtime
  const choice = require('/tools/pick-runtime.js')(WORK, src.commit_date); R.runtime_choice = choice;
  // The archive is extracted (and therefore can ever be executed) ONLY after its SHA-256 matched the official checksum list.
  // Missing, malformed or mismatching checksum information => the reconstruction is classified unavailable (H3), honestly.
  try {
    const index = JSON.parse((await get('https://nodejs.org/dist/index.json')).toString());
    const rec = await acquireRuntime({ get, line: choice.line, index, extract: async tgz => {
      fs.mkdirSync(OLD, { recursive: true }); fs.writeFileSync('/tmp/old.tgz', tgz); cp.execSync(`tar -xzf /tmp/old.tgz -C ${OLD} --strip-components=1`); } });
    R.runtime = rec;   // records line, version, source URL, checksum URL, expected digest, actual digest, verification outcome
    if (!rec.verified) throw new Error('runtime integrity not verified (' + rec.verification + ')');
    rec.reports = cp.execSync(`${OLD}/bin/node -v`, { encoding: 'utf8' }).trim();
  } catch (e) { R.level = 'H3'; R.runtime_unavailable = true; R.reason = 'historical runtime unavailable: ' + e.message; save(); }
  // 2. dependencies: exact lock file if present (H1 candidate), otherwise as of the commit date (H2 candidate)
  const hasLock = ['package-lock.json', 'npm-shrinkwrap.json'].find(f => fs.existsSync(path.join(WORK, f)));
  const npmFlags = '--ignore-scripts --no-audit --no-fund --loglevel=error';
  let inst = hasLock ? sh('install-locked', `npm ci ${npmFlags}`) : null;
  R.install = { lock_file: hasLock || null, method: null };
  if (inst && inst.status === 0) R.install.method = 'lock file';
  else { inst = sh('install-asof', `npm install ${npmFlags} --before="${src.commit_date}"`); if (inst.status === 0) R.install.method = 'as of commit date'; }
  if (!R.install.method) { R.level = 'H3'; R.reason = R.reason || 'dependencies could not be installed (lock file or as-of-date)'; }
  else { try { const lock = JSON.parse(fs.readFileSync(path.join(WORK, 'node_modules/.package-lock.json'), 'utf8')).packages; const ps = Object.values(lock);
    R.install.packages = ps.length; R.install.without_integrity = ps.filter(p => !p.integrity).length; R.install.install_scripts_skipped = ps.filter(p => p.hasInstallScript).length;
    R.install.non_registry = ps.filter(p => p.resolved && !p.resolved.startsWith('https://registry.npmjs.org/')).length; } catch (e) { R.install.packages = null; } }
  save();
  // 3. historical test runs (twice), without the old npm: run the test script with the old node first on PATH
  if (R.level !== 'H3' && R.runtime && R.runtime.verified === true) {   // never run tests with a runtime that was not integrity-verified
    const env = { PATH: `${WORK}/node_modules/.bin:${OLD}/bin:/usr/bin:/bin`, HOME: '/tmp/home', CI: 'true', ...PUBLIC };
    R.historical_runs = [];
    for (const i of [1, 2]) { const r = sh('historical-test-' + i, testScript || 'false', { env });
      const j = sh('historical-mocha-json-' + i, `mocha --reporter json ${/^mocha(\s|$)/.test(testScript) ? testScript.replace(/^mocha/, '').replace(/(-R|--reporter)[ =]\S+/, '') : ''}`, { env });
      const m = mochaResults(j.stdout || ''); R.historical_runs.push({ test_script_exit: r.status, structured: !!m, passes: m ? m.passes.length : null, failures: m ? m.failures.length : null, _p: m ? m.passes : [] }); }
    const [a, b] = R.historical_runs; const stable = a._p.filter(t => b._p.includes(t)); R.stable_passing_tests = stable.length;
    fs.writeFileSync(path.join(OUT, 'baseline-passing-tests.json'), JSON.stringify(stable, null, 1)); R.historical_runs.forEach(x => delete x._p);
    const ran = a.structured && b.structured && stable.length > 0;
    R.level = !ran ? 'H3' : (R.install.method === 'lock file' && R.install.without_integrity === 0 ? 'H1' : 'H2');
    if (!ran) R.reason = 'tests did not produce structured passing results in the historical runtime';
  }
  save();
  // 4. is it broken today? fresh copy, current runtime, no date limit
  cp.execSync(`cp -a /snap/subject ${TODAY}`);
  const ti = sh('today-install', `npm install ${npmFlags}`, { cwd: TODAY });
  const tt = ti.status === 0 ? sh('today-test', testScript || 'false', { cwd: TODAY, env: { PATH: `${TODAY}/node_modules/.bin:${path.dirname(process.execPath)}:/usr/bin:/bin`, HOME: '/tmp/home', CI: 'true', ...PUBLIC } }) : null;
  R.today = { runtime: process.version, install_exit: ti.status, test_exit: tt ? tt.status : null, broken_today: ti.status !== 0 || !tt || tt.status !== 0 };
  R.finished = new Date().toISOString(); save();
})().catch(e => { R.level = R.level || 'H3'; R.reason = 'harness error: ' + e.message; R.harness_error = true; save(); });
