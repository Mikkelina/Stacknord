'use strict';

require('dotenv').config();
const path = require('node:path');
const Database = require('better-sqlite3');

const email = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
  console.error('Set ADMIN_EMAIL to the email address of an already-created account.');
  process.exit(1);
}
const dbPath = process.env.DATABASE_PATH || path.join(__dirname, '..', 'data', 'stacknord.sqlite');
const db = new Database(dbPath);
try {
  const user = db.prepare('SELECT id, email FROM users WHERE email = ?').get(email);
  if (!user) {
    console.error('No account found for ADMIN_EMAIL. Register that account first, then rerun this command.');
    process.exitCode = 1;
  } else {
    const columns = new Set(db.prepare('PRAGMA table_info(users)').all().map((column) => column.name));
    if (!columns.has('role')) db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'");
    if (!columns.has('account_status')) db.exec("ALTER TABLE users ADD COLUMN account_status TEXT NOT NULL DEFAULT 'active'");
    if (!columns.has('banned_at')) db.exec('ALTER TABLE users ADD COLUMN banned_at TEXT');
    if (!columns.has('ban_reason')) db.exec('ALTER TABLE users ADD COLUMN ban_reason TEXT');
    db.exec(`CREATE TABLE IF NOT EXISTS admin_roles (name TEXT PRIMARY KEY, permissions_json TEXT NOT NULL, is_builtin INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`);
    db.prepare(`INSERT INTO admin_roles (name, permissions_json, is_builtin) VALUES ('admin', ?, 1) ON CONFLICT(name) DO NOTHING`)
      .run(JSON.stringify(['users.read', 'users.manage', 'orders.read', 'orders.manage', 'activity.read', 'roles.manage']));
    db.prepare("UPDATE users SET role = 'admin', account_status = 'active' WHERE id = ?").run(user.id);
    console.log(`Administrator role granted to ${user.email}. No password or secret was printed.`);
  }
} finally {
  db.close();
}
