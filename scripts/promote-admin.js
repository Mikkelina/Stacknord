'use strict';

require('dotenv').config();
const path = require('node:path');
const Database = require('better-sqlite3');

const email = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
  console.error('Set ADMIN_EMAIL to the email address of an already-created account.');
  process.exit(1);
}
const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'data', 'stacknord.sqlite');
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
    db.prepare("UPDATE users SET role = 'admin', account_status = 'active' WHERE id = ?").run(user.id);
    console.log(`Administrator role granted to ${user.email}. No password or secret was printed.`);
  }
} finally {
  db.close();
}
