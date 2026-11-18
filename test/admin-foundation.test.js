'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Database = require('better-sqlite3');
const { installAdminPanel, PERMISSIONS, BUILTIN_ROLES } = require('../admin-panel');
const { installAdminExtras } = require('../admin-extras');

function makeApp() {
  const routes = new Map();
  return {
    routes,
    get(path, ...handlers) { routes.set(`GET ${path}`, handlers); },
    post(path, ...handlers) { routes.set(`POST ${path}`, handlers); }
  };
}

function makeDb() {
  const db = new Database(':memory:');
  db.exec(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
      plan_id TEXT NOT NULL, period TEXT NOT NULL, amount_nok INTEGER NOT NULL,
      payment_method TEXT NOT NULL, payment_status TEXT NOT NULL DEFAULT 'Venter på betaling',
      stripe_session_id TEXT UNIQUE, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE sessions (sid TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at INTEGER NOT NULL);
  `);
  return db;
}

test('admin modules migrate a fresh SQLite DB and register guarded routes', () => {
  const db = makeDb();
  const app = makeApp();
  const helpers = {
    csrf: () => '<input type="hidden">',
    page: (_req, title, content) => `<title>${title}</title>${content}`
  };
  installAdminPanel(app, db, helpers);
  installAdminExtras(app, db, helpers);

  const columns = db.prepare('PRAGMA table_info(users)').all().map((column) => column.name);
  assert.ok(columns.includes('role'));
  assert.ok(columns.includes('account_status'));
  assert.ok(db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'support_tickets'").get());
  assert.ok(db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'admin_audit_log'").get());
  for (const route of [
    'GET /admin/login', 'POST /admin/login', 'GET /admin/users',
    'GET /admin/roles', 'GET /admin/support', 'POST /admin/support/:id',
    'POST /admin/orders/:id/review', 'GET /support/:id'
  ]) assert.ok(app.routes.has(route), `missing route ${route}`);
  assert.ok(PERMISSIONS.includes('orders.manage'));
  assert.ok(BUILTIN_ROLES.admin.includes('roles.manage'));
  assert.ok(!BUILTIN_ROLES.support.includes('roles.manage'));
  db.close();
});

test('support ticket access is owner-scoped in the SQL query', () => {
  const source = require('node:fs').readFileSync(require('node:path').join(__dirname, '..', 'admin-extras.js'), 'utf8');
  assert.match(source, /WHERE id = \? AND user_id = \?/);
  assert.match(source, /Stripe-status kan ikke endres manuelt/);
});
