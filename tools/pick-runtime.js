// Chooses the Node.js release line a project was written for. Trusted code; reads files as data only.
// Order: version file -> highest version in old CI settings -> long-term-support line current at the last commit,
// raised to the project's declared minimum if that is higher.
const fs = require('fs'), path = require('path');
const LINES = ['0.10', '0.12', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26'];
const LTS_BY_DATE = [['2015-10-01', '0.10'], ['2016-10-01', '4'], ['2017-10-01', '6'], ['2018-10-01', '8'], ['2019-10-01', '10'],
  ['2020-10-01', '12'], ['2021-10-01', '14'], ['2022-10-01', '16'], ['2023-10-01', '18'], ['2024-10-01', '20'], ['2025-10-01', '22'], ['2026-10-01', '24'], ['9999-01-01', '26']];
const norm = v => { const m = String(v).match(/(\d+)(?:\.(\d+))?/); if (!m) return null; const a = +m[1]; const l = a === 0 ? (m[2] ? '0.' + m[2] : null) : String(a); return l; };
const rank = l => { const i = LINES.indexOf(l); return i < 0 ? (l && l.startsWith('0.') ? -1 : null) : i; };
const read = (d, f) => { try { return fs.readFileSync(path.join(d, f), 'utf8'); } catch (e) { return null; } };
function pick(dir, commitDate) {
  for (const f of ['.nvmrc', '.node-version']) { const s = read(dir, f); const l = s && norm(s.trim()); if (l && /^v?\d/.test(s.trim())) return fit(l, 'version file ' + f); }
  const t = read(dir, '.travis.yml');
  if (t) { const m = t.match(/node_js:[ \t]*((?:\r?\n[ \t]*-[ \t]*.+)+|\[.*\]|\S+)/); if (m) { const vs = (m[1].match(/["']?v?(\d+(?:\.\d+)?)/g) || []).map(norm).filter(l => rank(l) !== null);
    if (vs.length) return fit(vs.sort((a, b) => rank(b) - rank(a))[0], 'highest version in .travis.yml'); } }
  let byDate = '26'; for (const [until, line] of LTS_BY_DATE) if (String(commitDate) < until) { byDate = line; break; }
  let min = null; try { const e = (JSON.parse(read(dir, 'package.json')) || {}).engines; const s = e && (e.node || (Array.isArray(e) ? e.join(' ') : '')); if (s) min = norm(String(s).replace(/^[^\d]*/, '')); } catch (e) { }
  if (min && rank(min) !== null && rank(min) > rank(byDate)) return fit(min, 'declared minimum in engines');
  return fit(byDate, 'long-term-support line at last commit date ' + String(commitDate).slice(0, 10));
}
function fit(line, rule) { if (rank(line) === -1) return { line: '0.10', rule: rule + ' (asked for ' + line + ', older than 0.10; using 0.10)' }; return { line, rule }; }
module.exports = pick;
if (require.main === module) console.log(JSON.stringify(pick(process.argv[2], process.argv[3])));
