'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.join(__dirname, '..');
const serverPath = path.join(root, 'server.js');
let source = fs.readFileSync(serverPath, 'utf8');
const original = source;
const imports = [
  "const { installAdminPanel } = require('./admin-panel');",
  "const { installAdminExtras } = require('./admin-extras');"
];
const importAnchor = "const helmet = require('helmet');";
if (!source.includes(importAnchor) && imports.some((line) => !source.includes(line))) {
  throw new Error('Could not find expected import anchor; no changes made.');
}
if (!source.includes(imports[0])) source = source.replace(importAnchor, `${importAnchor}\n${imports[0]}`);
if (!source.includes(imports[1])) source = source.replace(imports[0], `${imports[0]}\n${imports[1]}`);

const installLines = [
  'installAdminPanel(app, db, { csrf, page });',
  'installAdminExtras(app, db, { csrf, page });'
];
const routeAnchor = "app.get('/', (req, res) =>";
if (!source.includes(routeAnchor) && installLines.some((line) => !source.includes(line))) {
  throw new Error('Could not find expected route anchor; no changes made.');
}
if (!source.includes(installLines[0])) source = source.replace(routeAnchor, `${installLines[0]}\n${installLines[1]}\n\n${routeAnchor}`);
else if (!source.includes(installLines[1])) source = source.replace(installLines[0], `${installLines[0]}\n${installLines[1]}`);

const marker = '// ADMIN_ACCOUNT_STATUS_ENFORCEMENT';
const staticAnchor = "app.use(express.static(path.join(__dirname, 'public')));";
if (!source.includes(marker)) {
  if (!source.includes(staticAnchor)) throw new Error('Could not find expected middleware anchor; no changes made.');
  const guard = `${marker}
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
  source = source.replace(staticAnchor, `${guard}\n${staticAnchor}`);
}
if (source === original) {
  console.log('Admin integration already present; no changes needed.');
  process.exit(0);
}
const tempPath = `${serverPath}.check-${process.pid}.js`;
try {
  fs.writeFileSync(tempPath, source, { flag: 'wx', mode: 0o600 });
  const check = spawnSync(process.execPath, ['--check', tempPath], { encoding: 'utf8' });
  if (check.status !== 0) throw new Error(check.stderr || check.stdout || 'Syntax validation failed.');
} finally {
  try { fs.unlinkSync(tempPath); } catch {}
}
const backup = `${serverPath}.pre-admin-${new Date().toISOString().replace(/[:.]/g, '-')}.bak`;
fs.copyFileSync(serverPath, backup, fs.constants.COPYFILE_EXCL);
const writePath = `${serverPath}.tmp-${process.pid}`;
try {
  fs.writeFileSync(writePath, source, { flag: 'wx', mode: 0o600 });
  fs.renameSync(writePath, serverPath);
  console.log(`Integrated admin panel, support desk and ban enforcement. Backup: ${path.basename(backup)}`);
} catch (error) {
  try { fs.unlinkSync(writePath); } catch {}
  throw error;
}
