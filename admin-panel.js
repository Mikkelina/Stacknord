'use strict';

const bcrypt = require('bcryptjs');

const PERMISSIONS = Object.freeze([
  'users.read', 'users.manage', 'orders.read', 'orders.manage',
  'activity.read', 'roles.manage'
]);
const BUILTIN_ROLES = Object.freeze({
  admin: PERMISSIONS,
  moderator: ['users.read', 'users.manage', 'orders.read', 'orders.manage', 'activity.read'],
  support: ['users.read', 'orders.read']
});

function escapeHtml(value = '') {
  return String(value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[char]));
}

function installAdminPanel(app, db, options = {}) {
  const { csrf, page } = options;
  if (typeof csrf !== 'function' || typeof page !== 'function') {
    throw new Error('Admin panel requires the host application csrf() and page() helpers.');
  }

  // Additive SQLite migration; existing customer/order data is preserved.
  const userColumns = new Set(db.prepare('PRAGMA table_info(users)').all().map((column) => column.name));
  if (!userColumns.has('role')) db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'");
  if (!userColumns.has('account_status')) db.exec("ALTER TABLE users ADD COLUMN account_status TEXT NOT NULL DEFAULT 'active'");
  if (!userColumns.has('banned_at')) db.exec('ALTER TABLE users ADD COLUMN banned_at TEXT');
  if (!userColumns.has('ban_reason')) db.exec('ALTER TABLE users ADD COLUMN ban_reason TEXT');
  db.exec(`
    CREATE TABLE IF NOT EXISTS admin_roles (
      name TEXT PRIMARY KEY,
      permissions_json TEXT NOT NULL,
      is_builtin INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS admin_audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_user_id INTEGER REFERENCES users(id),
      action TEXT NOT NULL,
      target_user_id INTEGER REFERENCES users(id),
      details_json TEXT NOT NULL DEFAULT '{}',
      ip_address TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit_log(created_at);
    CREATE INDEX IF NOT EXISTS idx_admin_audit_actor ON admin_audit_log(actor_user_id);
  `);
  const saveRole = db.prepare(`INSERT INTO admin_roles (name, permissions_json, is_builtin)
    VALUES (?, ?, 1) ON CONFLICT(name) DO NOTHING`);
  for (const [name, permissions] of Object.entries(BUILTIN_ROLES)) {
    saveRole.run(name, JSON.stringify(permissions));
  }

  function record(req, action, targetUserId = null, details = {}) {
    // Never log credentials, session IDs, or arbitrary request bodies.
    const ip = String(req.ip || req.socket?.remoteAddress || '').slice(0, 64) || null;
    db.prepare(`INSERT INTO admin_audit_log (actor_user_id, action, target_user_id, details_json, ip_address)
      VALUES (?, ?, ?, ?, ?)`).run(
      req.session.user.id, action, targetUserId,
      JSON.stringify(details).slice(0, 2000), ip
    );
  }

  function currentAdmin(req) {
    if (!req.session.user || !req.session.adminAuthenticatedAt) return null;
    const user = db.prepare('SELECT id, name, email, role, account_status FROM users WHERE id = ?')
      .get(req.session.user.id);
    if (!user || user.account_status !== 'active') return null;
    const role = db.prepare('SELECT permissions_json FROM admin_roles WHERE name = ?').get(user.role);
    if (!role) return null;
    let permissions;
    try { permissions = JSON.parse(role.permissions_json); } catch { return null; }
    return { ...user, permissions: new Set(permissions) };
  }

  function requireAdmin(req, res, next) {
    const admin = currentAdmin(req);
    if (!admin) return res.redirect('/admin/login');
    req.admin = admin;
    next();
  }

  function requirePermission(permission) {
    return (req, res, next) => {
      if (!req.admin.permissions.has(permission)) {
        return res.status(403).send(page(req, 'Ingen tilgang', '<section class="form-card"><h1>Ingen tilgang</h1><p>Rollen din har ikke tillatelse til denne handlingen.</p></section>'));
      }
      next();
    };
  }

  app.get('/admin/login', (req, res) => {
    const admin = currentAdmin(req);
    if (admin) return res.redirect('/admin');
    res.send(page(req, 'Admininnlogging', `<section class="form-card narrow-card"><div class="eyebrow">BESKYTTET OMRÅDE</div><h1>Admininnlogging</h1><form method="post" action="/admin/login">${csrf(req)}<label>E-post<input name="email" type="email" autocomplete="username" required maxlength="254"></label><label>Passord<input name="password" type="password" autocomplete="current-password" required maxlength="200"></label><button class="button">Logg inn</button></form></section>`));
  });

  app.post('/admin/login', async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const user = db.prepare('SELECT id, name, email, password_hash, role, account_status FROM users WHERE email = ?').get(email);
    const role = user && db.prepare('SELECT permissions_json FROM admin_roles WHERE name = ?').get(user.role);
    let hasAdminRole = false;
    if (role) {
      try { hasAdminRole = JSON.parse(role.permissions_json).length > 0; } catch { hasAdminRole = false; }
    }
    if (!user || user.account_status !== 'active' || !hasAdminRole || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).send(page(req, 'Admininnlogging', '<div class="notice notice-error">E-post, passord eller tilgang stemmer ikke.</div><a href="/admin/login">Prøv igjen</a>'));
    }
    req.session.regenerate((error) => {
      if (error) return res.status(500).send('Kunne ikke starte sikker adminøkt.');
      req.session.user = { id: user.id, name: user.name, email: user.email };
      req.session.adminAuthenticatedAt = Date.now();
      req.session.csrfToken = require('node:crypto').randomBytes(32).toString('hex');
      const adminReq = { ...req, session: req.session, ip: req.ip, socket: req.socket };
      // Login event is kept separate from privileged mutation events.
      db.prepare(`INSERT INTO admin_audit_log (actor_user_id, action, ip_address) VALUES (?, ?, ?)`)
        .run(user.id, 'admin.login', String(req.ip || '').slice(0, 64) || null);
      res.redirect('/admin');
    });
  });

  app.post('/admin/logout', requireAdmin, (req, res) => {
    db.prepare(`INSERT INTO admin_audit_log (actor_user_id, action, ip_address) VALUES (?, ?, ?)`)
      .run(req.admin.id, 'admin.logout', String(req.ip || '').slice(0, 64) || null);
    req.session.destroy(() => res.redirect('/admin/login'));
  });

  app.get('/admin', requireAdmin, (req, res) => {
    const counts = {
      users: db.prepare('SELECT COUNT(*) AS count FROM users').get().count,
      active: db.prepare("SELECT COUNT(*) AS count FROM users WHERE account_status = 'active'").get().count,
      banned: db.prepare("SELECT COUNT(*) AS count FROM users WHERE account_status = 'banned'").get().count,
      orders: db.prepare('SELECT COUNT(*) AS count FROM orders').get().count
    };
    const nav = '<a href="/admin/users">Brukere</a> <a href="/admin/orders">Bestillinger</a> <a href="/admin/activity">Aktivitetslogg</a>';
    res.send(page(req, 'Administrasjon', `<section class="page-heading"><div class="eyebrow">ADMINISTRASJON</div><h1>Adminpanel</h1><p>Innlogget som ${escapeHtml(req.admin.email)} (${escapeHtml(req.admin.role)}).</p><nav>${nav}</nav><form method="post" action="/admin/logout">${csrf(req)}<button class="button">Logg ut av admin</button></form></section><section class="table-card"><h2>Oversikt</h2><p>Brukere: ${counts.users} · Aktive: ${counts.active} · Utestengt: ${counts.banned} · Bestillinger: ${counts.orders}</p></section>`));
  });

  app.get('/admin/users', requireAdmin, requirePermission('users.read'), (req, res) => {
    const users = db.prepare('SELECT id, name, email, role, account_status, created_at, banned_at, ban_reason FROM users ORDER BY id DESC LIMIT 200').all();
    const rows = users.map((user) => `<tr><td>${user.id}</td><td>${escapeHtml(user.name)}<small>${escapeHtml(user.email)}</small></td><td>${escapeHtml(user.role)}</td><td>${escapeHtml(user.account_status)}</td><td>${escapeHtml(user.created_at)}</td><td>${user.account_status === 'banned' ? `<form method="post" action="/admin/users/${user.id}/unban">${csrf(req)}<button>Opphev utestengelse</button></form>` : `<form method="post" action="/admin/users/${user.id}/ban">${csrf(req)}<label>Begrunnelse<input name="reason" maxlength="500" required></label><button>Utesteng permanent</button></form>`}</td></tr>`).join('');
    const createForm = req.admin.permissions.has('users.manage') ? `<section class="form-card"><h2>Opprett brukerkonto</h2><form method="post" action="/admin/users">${csrf(req)}<label>Navn<input name="name" required maxlength="100"></label><label>E-post<input name="email" type="email" required maxlength="254"></label><label>Midlertidig passord<input name="password" type="password" required minlength="12" maxlength="200" autocomplete="new-password"></label><button class="button">Opprett bruker</button></form></section>` : '';
    res.send(page(req, 'Brukere', `<section class="page-heading"><h1>Brukeradministrasjon</h1><p>Viser inntil 200 kontoer. IP-adresser vises ikke i brukerlisten.</p></section>${createForm}<section class="table-card"><div class="table-scroll"><table><thead><tr><th>ID</th><th>Bruker</th><th>Rolle</th><th>Status</th><th>Opprettet</th><th>Handling</th></tr></thead><tbody>${rows || '<tr><td colspan="6">Ingen brukere.</td></tr>'}</tbody></table></div></section>`));
  });

  app.post('/admin/users', requireAdmin, requirePermission('users.manage'), async (req, res) => {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!name || name.length > 100 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 || password.length < 12 || password.length > 200) {
      return res.status(400).send(page(req, 'Opprett bruker', '<div class="notice notice-error">Kontroller navn, e-post og at passordet har minst 12 tegn.</div><a href="/admin/users">Tilbake</a>'));
    }
    try {
      const hash = await bcrypt.hash(password, 12);
      const result = db.prepare("INSERT INTO users (name, email, password_hash, role, account_status) VALUES (?, ?, ?, 'user', 'active')").run(name, email, hash);
      record(req, 'user.create', Number(result.lastInsertRowid), { email });
      res.redirect('/admin/users');
    } catch (error) {
      if (String(error.code).includes('SQLITE_CONSTRAINT')) return res.status(409).send(page(req, 'Opprett bruker', '<div class="notice notice-error">E-postadressen finnes allerede.</div><a href="/admin/users">Tilbake</a>'));
      throw error;
    }
  });

  app.post('/admin/users/:id/ban', requireAdmin, requirePermission('users.manage'), (req, res) => {
    const targetId = Number(req.params.id);
    const reason = String(req.body.reason || '').trim().slice(0, 500);
    const target = db.prepare('SELECT id, role, account_status FROM users WHERE id = ?').get(targetId);
    if (!target || target.account_status === 'banned' || !reason) return res.status(400).send('Ugyldig bruker eller begrunnelse.');
    if (target.role === 'admin') {
      const admins = db.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND account_status = 'active'").get().count;
      if (admins <= 1) return res.status(409).send('Kan ikke utestenge den siste aktive administratoren.');
    }
    db.prepare("UPDATE users SET account_status = 'banned', banned_at = CURRENT_TIMESTAMP, ban_reason = ? WHERE id = ?").run(reason, targetId);
    record(req, 'user.permanent_ban', targetId, { reason });
    res.redirect('/admin/users');
  });

  app.post('/admin/users/:id/unban', requireAdmin, requirePermission('users.manage'), (req, res) => {
    const targetId = Number(req.params.id);
    const target = db.prepare('SELECT id FROM users WHERE id = ?').get(targetId);
    if (!target) return res.status(404).send('Brukeren finnes ikke.');
    db.prepare("UPDATE users SET account_status = 'active', banned_at = NULL, ban_reason = NULL WHERE id = ?").run(targetId);
    record(req, 'user.unban', targetId);
    res.redirect('/admin/users');
  });

  app.get('/admin/orders', requireAdmin, requirePermission('orders.read'), (req, res) => {
    const orders = db.prepare(`SELECT o.id, o.user_id, u.email, o.plan_id, o.period, o.amount_nok, o.payment_method, o.payment_status, o.created_at
      FROM orders o JOIN users u ON u.id = o.user_id ORDER BY o.id DESC LIMIT 200`).all();
    const rows = orders.map((o) => `<tr><td>${o.id}</td><td>${escapeHtml(o.email)}</td><td>${escapeHtml(o.plan_id)} (${escapeHtml(o.period)})</td><td>${o.amount_nok} NOK</td><td>${escapeHtml(o.payment_method)}</td><td>${escapeHtml(o.payment_status)}</td><td>${escapeHtml(o.created_at)}</td></tr>`).join('');
    res.send(page(req, 'Bestillinger', `<section class="page-heading"><h1>Bestillinger</h1></section><section class="table-card"><div class="table-scroll"><table><thead><tr><th>ID</th><th>Kunde</th><th>Plan</th><th>Beløp</th><th>Betaling</th><th>Status</th><th>Opprettet</th></tr></thead><tbody>${rows || '<tr><td colspan="7">Ingen bestillinger.</td></tr>'}</tbody></table></div></section>`));
  });

  app.get('/admin/activity', requireAdmin, requirePermission('activity.read'), (req, res) => {
    const events = db.prepare(`SELECT a.id, a.action, a.actor_user_id, actor.email AS actor_email,
      a.target_user_id, a.details_json, a.ip_address, a.created_at
      FROM admin_audit_log a LEFT JOIN users actor ON actor.id = a.actor_user_id
      ORDER BY a.id DESC LIMIT 200`).all();
    const rows = events.map((event) => `<tr><td>${escapeHtml(event.created_at)}</td><td>${escapeHtml(event.action)}</td><td>${escapeHtml(event.actor_email || event.actor_user_id || '')}</td><td>${escapeHtml(event.target_user_id || '')}</td><td>${escapeHtml(event.ip_address || '')}</td><td>${escapeHtml(event.details_json)}</td></tr>`).join('');
    res.send(page(req, 'Aktivitetslogg', `<section class="page-heading"><h1>Adminaktivitetslogg</h1><p>Begrens tilgangen til denne siden. IP-adresser logges for administrative innlogginger og handlinger.</p></section><section class="table-card"><div class="table-scroll"><table><thead><tr><th>Tid</th><th>Handling</th><th>Admin</th><th>Bruker-ID</th><th>IP</th><th>Detaljer</th></tr></thead><tbody>${rows || '<tr><td colspan="6">Ingen hendelser.</td></tr>'}</tbody></table></div></section>`));
  });
}

module.exports = { installAdminPanel, PERMISSIONS, BUILTIN_ROLES };
