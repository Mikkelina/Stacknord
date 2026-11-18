'use strict';

// Apply the admin integration as a one-time, idempotent patch. A backup is
// created before writing; unexpected source layouts fail closed without edits.
const fs = require('node:fs');
const path = require('node:path');

const serverPath = path.join(__dirname, '..', 'server.js');
let source = fs.readFileSync(serverPath, 'utf8');
const original = source;

const importLine = "const { installAdminPanel } = require('./admin-panel');";
if (!source.includes(importLine)) {
  const importAnchor = "const helmet = require('helmet');";
  if (!source.includes(importAnchor)) throw new Error('Could not find server.js import anchor; no changes made.');
  source = source.replace(importAnchor, `${importAnchor}\n${importLine}`);
}

const mountLine = 'installAdminPanel(app, db, { csrf, page });';
if (!source.includes(mountLine)) {
  const routeAnchor = "app.get('/', (req, res) =>";
  if (!source.includes(routeAnchor)) throw new Error('Could not find route anchor; no changes made.');
  source = source.replace(routeAnchor, `${mountLine}\n\n${routeAnchor}`);
}

const enforcementMarker = '// ADMIN_ACCOUNT_STATUS_ENFORCEMENT';
if (!source.includes(enforcementMarker)) {
  const staticAnchor = "app.use(express.static(path.join(__dirname, 'public')));";
  if (!source.includes(staticAnchor)) throw new Error('Could not find middleware anchor; no changes made.');
  const enforcement = `${enforcementMarker}
app.use((req, res, next) => {
  const userId = req.session?.user?.id;
  if (!userId) return next();
  const account = db.prepare('SELECT account_status FROM users WHERE id = ?').get(userId);
  if (!account || account.account_status !== 'active') {
    return req.session.destroy(() => {
      res.clearCookie('stacknord.sid');
      res.status(403).send('Kontoen er deaktivert eller utestengt. Kontakt kundestøtte hvis du mener dette er feil.');
    });
  }
  next();
});
`;
  source = source.replace(staticAnchor, `${enforcement}\n${staticAnchor}`);
}

if (source === original) {
  console.log('Admin integration already present; no changes needed.');
  process.exit(0);
}

// Ensure the generated file parses before replacing the original.
try {
  // The actual server has runtime dependencies, so perform syntax-only validation.
  new Function(source.replace(/^require\('dotenv'\)\.config\(\);\s*/, ''));
} catch (error) {
  // new Function cannot parse top-level return/await and is not a suitable full
  // CommonJS parser. Use Node's syntax checker instead via a temporary file.
  const tempPath = `${serverPath}.syntax-check-${process.pid}.js`;
  try {
    fs.writeFileSync(tempPath, source, { flag: 'wx', mode: 0o600 });
    const { spawnSync } = require('node:child_process');
    const check = spawnSync(process.execPath, ['--check', tempPath], { encoding: 'utf8' });
    if (check.status !== 0) throw new Error(check.stderr || check.stdout || 'Syntax check failed.');
  } finally {
    try { fs.unlinkSync(tempPath); } catch {}
  }
}

const backupPath = `${serverPath}.pre-admin-${new Date().toISOString().replace(/[:.]/g, '-')}.bak`;
fs.copyFileSync(serverPath, backupPath, fs.constants.COPYFILE_EXCL);
const tempPath = `${serverPath}.tmp-${process.pid}`;
try {
  fs.writeFileSync(tempPath, source, { flag: 'wx', mode: 0o600 });
  fs.renameSync(tempPath, serverPath);
  console.log(`Integrated admin routes and account-ban enforcement. Backup: ${path.basename(backupPath)}`);
} catch (error) {
  try { fs.unlinkSync(tempPath); } catch {}
  throw error;
}
