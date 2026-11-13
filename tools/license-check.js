// License gate, run by the trusted intake job BEFORE any snapshot is published. Reads files as data; runs nothing.
// A source is accepted only if ALL hold:
//   1. GitHub's license detector (which reads the license text) names a supported license;
//   2. a license file exists at the repository root AND its text contains that license's operative wording;
//   3. the text carries no known restrictive addition;
//   4. the license declared in package.json, if any, is the same license.
// A file merely named LICENSE proves nothing and is refused. This is a policy check, not legal advice.
// usage: node license-check.js <srcDir> <spdxFromGitHub|NONE> <owner/repo> <sha> <commitDate> <symlinksRemoved> <outDir>
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const [src, apiSpdx, source, sha, date, links, outDir] = process.argv.slice(2);
const SUPPORTED = {
  'MIT': ['permission is hereby granted, free of charge, to any person obtaining a copy', 'the software is provided "as is", without warranty of any kind'],
  'ISC': ['permission to use, copy, modify, and', 'distribute this software for any purpose with or without fee is hereby granted', 'the software is provided "as is"'],
  '0BSD': ['permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted', 'the software is provided "as is"'],
  'BSD-2-Clause': ['redistribution and use in source and binary forms, with or without modification, are permitted', 'this software is provided by'],
  'BSD-3-Clause': ['redistribution and use in source and binary forms, with or without modification, are permitted', 'neither the name', 'this software is provided by'],
  'Apache-2.0': ['apache license', 'version 2.0', 'www.apache.org/licenses', 'grant of copyright license'],
};
const RESTRICTIVE = ['commons clause', 'non-commercial', 'noncommercial', 'not for commercial', 'gnu general public license', 'gnu affero', 'gnu lesser general public', 'server side public license', 'business source license', 'all rights reserved.\n\nno permission'];
const norm = t => t.toLowerCase().replace(/[“”]/g, '"').replace(/\s+/g, ' ');
const D = { v: 1, source, sha, commit_date: date, github_detected_spdx: apiSpdx, accepted: false, reasons: [] };
const refuse = r => { D.reasons.push(r); };
const rootFiles = fs.readdirSync(src).filter(f => { try { return fs.lstatSync(path.join(src, f)).isFile(); } catch (e) { return false; } });
const licFile = rootFiles.find(f => /^(licen[cs]e|copying)([.-].*)?$/i.test(f));
if (!SUPPORTED[apiSpdx]) refuse(`GitHub's detector reports "${apiSpdx}", which is not a supported license (${Object.keys(SUPPORTED).join(', ')})`);
if (!licFile) refuse('no license file at the repository root');
if (licFile) {
  const raw = fs.readFileSync(path.join(src, licFile)); const text = norm(raw.toString('utf8'));
  D.license_file = licFile; D.license_sha256 = crypto.createHash('sha256').update(raw).digest('hex'); D.license_bytes = raw.length;
  D.copyright_lines = raw.toString('utf8').split(/\r?\n/).filter(l => /copyright/i.test(l) && /\d{4}|\(c\)|©/i.test(l)).map(l => l.trim()).slice(0, 10);
  if (SUPPORTED[apiSpdx]) { const missing = SUPPORTED[apiSpdx].filter(m => !text.includes(m)); if (missing.length) refuse(`license file text lacks the operative wording of ${apiSpdx}: missing ${missing.length} of ${SUPPORTED[apiSpdx].length} required passages`); }
  const bad = RESTRICTIVE.filter(m => text.includes(m)); if (bad.length) refuse('license file contains restrictive wording: ' + bad.join('; '));
}
let declared = null;
try { const p = JSON.parse(fs.readFileSync(path.join(src, 'package.json'), 'utf8')); const l = p.license || (Array.isArray(p.licenses) ? p.licenses.map(x => x.type || x).join(' OR ') : null);
  declared = l && typeof l === 'object' ? (l.type || null) : l; } catch (e) { }
D.package_json_license = declared;
if (declared && String(declared).toLowerCase() !== String(apiSpdx).toLowerCase()) refuse(`package.json declares "${declared}" but the detected license is "${apiSpdx}"`);
D.notice_files = rootFiles.filter(f => /^(notice|authors|contributors|patents|copyright)([.-].*)?$/i.test(f));
D.accepted = D.reasons.length === 0;
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, 'license-decision.json'), JSON.stringify(D, null, 1));
if (!D.accepted) { console.error('LICENSE REFUSED: ' + D.reasons.join(' | ')); process.exit(1); }
fs.writeFileSync(path.join(outDir, 'SOURCE.json'), JSON.stringify({ source, sha, commit_date: date, symlinks_removed: Number(links) || 0, spdx: apiSpdx, license_file: licFile, license_sha256: D.license_sha256, notice_files: D.notice_files, copyright_lines: D.copyright_lines }) + '\n');
fs.writeFileSync(path.join(outDir, 'ATTRIBUTION.md'), [
  `# Attribution`, ``,
  `The folder \`subject/\` is a snapshot of https://github.com/${source} at commit \`${sha}\` (${date}).`,
  `It is the work of its original authors and remains under its original license: **${apiSpdx}**.`, ``,
  `- License text: \`subject/${licFile}\` (SHA-256 \`${D.license_sha256}\`), kept unmodified.`,
  `- Notice and author files kept unmodified: ${D.notice_files.length ? D.notice_files.map(f => '`subject/' + f + '`').join(', ') : 'none present at the repository root'}.`,
  `- Copyright lines found in the license file: ${D.copyright_lines.length ? D.copyright_lines.map(l => '"' + l + '"').join('; ') : 'none found'}.`, ``,
  `## Changes made to the original`, ``,
  `- The \`.github\` folder and \`.gitmodules\` file were removed, so the project's own automation cannot run here.`,
  `- ${Number(links) || 0} symbolic link(s) were removed.`,
  `- No other file was changed. Git history is not included; see the link above for it.`, ``,
  `This snapshot exists so that automated tests of this project can be run. It is not an endorsement by, or a release from, the original authors.`, ``].join('\n'));
console.log('LICENSE ACCEPTED: ' + apiSpdx + ' (' + licFile + ')');
