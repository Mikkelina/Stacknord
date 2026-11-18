'use strict';

const bcrypt = require('bcryptjs');
const crypto = require('node:crypto');

const PERMISSIONS = Object.freeze([
  'users.read', 'users.manage', 'orders.read', 'orders.manage',
  'activity.read', 'roles.manage'
]);
const BUILTIN_ROLES = Object.freeze({
  admin: PERMISSIONS,
  moderator: ['users.read', 'users.manage', 'orders.read', 'orders.manage'],
  support: ['users.read', 'orders.read']
});
const ADMIN_SESSION_MAX_AGE = 8 * 60 * 60 * 1000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 8;

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
    CREATE TABLE IF NOT EXISTS admin_login_attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip_address TEXT NOT NULL,
      attempted_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit_log(created_at);
    CREATE INDEX IF NOT EXISTS idx_admin_audit_actor ON admin_audit_log(actor_user_id);
    CREATE INDEX IF NOT EXISTS idx_admin_attempts_ip_time ON admin_login_attempts(ip_address, attempted_at);
  `);
  const saveRole = db.prepare(`INSERT INTO admin_roles (name, permissions_json, is_builtin)
    VALUES (?, ?, 1) ON CONFLICT(name) DO NOTHING`);
  for (const [name, permissions] of Object.entries(BUILTIN_ROLES)) {
    saveRole.run(name, JSON.stringify(permissions));
  }

  function clientIp(req) {
    // Express req.ip uses the configured proxy trust policy. Do not trust arbitrary X-Forwarded-For here.
    return String(req.ip || req.socket?.remoteAddress || '').slice(0, 64) || 'unknown';
  }

  function record(req, action, targetUserId = null, details = {}) {
    db.prepare(`INSERT INTO admin_audit_log (actor_user_id, action, target_user_id, details_json, ip_address)
      VALUES (?, ?, ?, ?, ?)`).run(
      req.admin?.id || req.session?.user?.id || null, action, targetUserId,
      JSON.stringify(details).slice(0, 2000), clientIp(req)
    );
  }

  function currentAdmin(req) {
    const authenticatedAt = Number(req.session?.adminAuthenticatedAt || 0);
    if (!req.session?.user || !authenticatedAt || Date.now() - authenticatedAt > ADMIN_SESSION_MAX_AGE) return null;
    const user = db.prepare('SELECT id, name, email, role, account_status FROM users WHERE id = ?')
      .get(req.session.user.id);
    if (!user || user.account_status !== 'active') return null;
    const role = db.prepare('SELECT permissions_json FROM admin_roles WHERE name = ?').get(user.role);
    if (!role) return null;
    let permissions;
    try { permissions = JSON.parse(role.permissions_json); } catch { return null; }
    if (!Array.isArray(permissions) || permissions.some((permission) => !PERMISSIONS.includes(permission))) return null;
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

  function loginBlocked(ip) {
    const cutoff = Date.now() - LOGIN_WINDOW_MS;
    db.prepare('DELETE FROM admin_login_attempts WHERE attempted_at < ?').run(cutoff);
    return db.prepare('SELECT COUNT(*) AS count FROM admin_login_attempts WHERE ip_address = ? AND attempted_at >= ?')
      .get(ip, cutoff).count >= LOGIN_MAX_ATTEMPTS;
  }

  app.get('/admin/login', (req, res) => {
    const admin = currentAdmin(req);
    if (admin) return res.redirect('/admin');
    res.set('Cache-Control', 'no-store');
    res.send(page(req, 'Admininnlogging', `<section class="form-card narrow-card"><div class="eyebrow">BESKYTTET OMRÅDE</div><h1>Admininnlogging</h1><form method="post" action="/admin/login">${csrf(req)}<label>E-post<input name="email" type="email" autocomplete="username" required maxlength="254"></label><label>Passord<input name="password" type="password" autocomplete="current-password" required maxlength="200"></label><button class="button">Logg inn</button></form></section>`));
  });

  app.post('/admin/login', async (req, res) => {
    const ip = clientIp(req);
    if (loginBlocked(ip)) return res.status(429).send('For mange forsøk. Vent litt og prøv igjen.');
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const user = db.prepare('SELECT id, name, email, password_hash, role, account_status FROM users WHERE email = ?').get(email);
    const role = user && db.prepare('SELECT permissions_json FROM admin_roles WHERE name = ?').get(user.role);
    let hasStaffAccess = false;
    if (role && user.account_status === 'active') {
      try {
        const permissions = JSON.parse(role.permissions_json);
        hasStaffAccess = Array.isArray(permissions) && permissions.some((permission) => PERMISSIONS.includes(permission));
      } catch { hasStaffAccess = false; }
    }
    const passwordMatches = user ? await bcrypt.compare(password, user.password_hash) : false;
    if (!user || !hasStaffAccess || !passwordMatches) {
      db.prepare('INSERT INTO admin_login_attempts (ip_address, attempted_at) VALUES (?, ?)').run(ip, Date.now());
      return res.status(401).send(page(req, 'Admininnlogging', '<div class="notice notice-error">E-post, passord eller tilgang stemmer ikke.</div><a href="/admin/login">Prøv igjen</a>'));
    }
    req.session.regenerate((error) => {
      if (error) return res.status(500).send('Kunne ikke starte sikker adminøkt.');
      req.session.user = { id: user.id, name: user.name, email: user.email };
      req.session.adminAuthenticatedAt = Date.now();
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');
      db.prepare(`INSERT INTO admin_audit_log (actor_user_id, action, ip_address) VALUES (?, ?, ?)`)
        .run(user.id, 'admin.login', ip);
      res.redirect('/admin');
    });
  });

  app.post('/admin/logout', requireAdmin, (req, res) => {
    record(req, 'admin.logout');
    req.session.destroy(() => res.redirect('/admin/login'));
  });

  app.get('/admin', requireAdmin, (req, res) => {
    res.set('Cache-Control', 'no-store');
    const counts = {
      users: db.prepare('SELECT COUNT(*) AS count FROM users').get().count,
      active: db.prepare("SELECT COUNT(*) AS count FROM users WHERE account_status = 'active'").get().count,
      banned: db.prepare("SELECT COUNT(*) AS count FROM users WHERE account_status = 'banned'").get().count,
      orders: db.prepare('SELECT COUNT(*) AS count FROM orders').get().count
    };
    const links = [];
    if (req.admin.permissions.has('users.read')) links.push('<a href="/admin/users">Brukere</a>');
    if (req.admin.permissions.has('orders.read')) links.push('<a href="/admin/orders">Bestillinger</a>');
    if (req.admin.permissions.has('activity.read')) links.push('<a href="/admin/activity">Aktivitetslogg</a>');
    if (req.admin.permissions.has('roles.manage')) links.push('<a href="/admin/roles">Roller</a>');
    res.send(page(req, 'Administrasjon', `<section class="page-heading"><div class="eyebrow">ADMINISTRASJON</div><h1>Adminpanel</h1><p>Innlogget som ${escapeHtml(req.admin.email)} (${escapeHtml(req.admin.role)}).</p><nav>${links.join(' ')}</nav><form method="post" action="/admin/logout">${csrf(req)}<button class="button">Logg ut av admin</button></form></section><section class="table-card"><h2>Oversikt</h2><p>Brukere: ${counts.users} · Aktive: ${counts.active} · Utestengt: ${counts.banned} · Bestillinger: ${counts.orders}</p></section>`));
  });

  app.get('/admin/users', requireAdmin, requirePermission('users.read'), (req, res) => {
    res.set('Cache-Control', 'no-store');
    const users = db.prepare('SELECT id, name, email, role, account_status, created_at, banned_at, ban_reason FROM users ORDER BY id DESC LIMIT 200').all();
    const roles = db.prepare('SELECT name FROM admin_roles ORDER BY name').all().map((row) => row.name);
    const rows = users.map((user) => {
      const ban = req.admin.permissions.has('users.manage')
        ? (user.account_status === 'banned'
          ? `<form method="post" action="/admin/users/${user.id}/unban">${csrf(req)}<button>Opphev utestengelse</button></form>`
          : `<form method="post" action="/admin/users/${user.id}/ban">${csrf(req)}<label>Begrunnelse<input name="reason" maxlength="500" required></label><button>Utesteng permanent</button></form>`)
        : '';
      const roleControl = req.admin.permissions.has('roles.manage')
        ? `<form method="post" action="/admin/users/${user.id}/role">${csrf(req)}<select name="role">${roles.map((role) => `<option value="${escapeHtml(role)}" ${role === user.role ? 'selected' : ''}>${escapeHtml(role)}</option>`).join('')}</select><button>Sett rolle</button></form>`
        : escapeHtml(user.role);
      return `<tr><td>${user.id}</td><td>${escapeHtml(user.name)}<small>${escapeHtml(user.email)}</small></td><td>${roleControl}</td><td>${escapeHtml(user.account_status)}${user.ban_reason ? `<small>${escapeHtml(user.ban_reason)}</small>` : ''}</td><td>${escapeHtml(user.created_at)}</td><td>${ban}</td></tr>`;
    }).join('');
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
    if (targetId === req.admin.id) return res.status(409).send('Du kan ikke utestenge din egen konto.');
    if (target.role !== 'user' && !req.admin.permissions.has('roles.manage')) return res.status(403).send('Kun en administrator kan utestenge en medarbeider.');
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

  app.post('/admin/users/:id/role', requireAdmin, requirePermission('roles.manage'), (req, res) => {
    const targetId = Number(req.params.id);
    const roleName = String(req.body.role || '');
    const target = db.prepare('SELECT id, role FROM users WHERE id = ?').get(targetId);
    const role = db.prepare('SELECT name FROM admin_roles WHERE name = ?').get(roleName);
    if (!target || !role) return res.status(400).send('Ugyldig bruker eller rolle.');
    if (targetId === req.admin.id && roleName !== 'admin') return res.status(409).send('Du kan ikke fjerne din egen administratorrolle.');
    if (target.role === 'admin' && roleName !== 'admin') {
      const admins = db.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND account_status = 'active'").get().count;
      if (admins <= 1) return res.status(409).send('Kan ikke fjerne den siste aktive administratoren.');
    }
    db.prepare('UPDATE users SET role = ? WHERE id = ?').run(roleName, targetId);
    record(req, 'user.role_change', targetId, { from: target.role, to: roleName });
    res.redirect('/admin/users');
  });

  app.get('/admin/roles', requireAdmin, requirePermission('roles.manage'), (req, res) => {
    const roles = db.prepare('SELECT name, permissions_json, is_builtin, created_at FROM admin_roles ORDER BY is_builtin DESC, name').all();
    const roleRows = roles.map((role) => {
      let selected = [];
      try { selected = JSON.parse(role.permissions_json); } catch { /* display empty on corrupt value */ }
      return `<tr><td>${escapeHtml(role.name)}</td><td>${role.is_builtin ? 'Innebygd' : 'Egendefinert'}</td><td>${selected.map(escapeHtml).join(', ') || 'Ingen'}</td><td>${db.prepare('SELECT COUNT(*) AS count FROM users WHERE role = ?').get(role.name).count}</td></tr>`;
    }).join('');
    const permissionInputs = PERMISSIONS.filter((permission) => permission !== 'roles.manage')
      .map((permission) => `<label><input type="checkbox" name="permissions" value="${escapeHtml(permission)}"> ${escapeHtml(permission)}</label>`).join('');
    res.send(page(req, 'Roller', `<section class="page-heading"><h1>Roller og tillatelser</h1><p>Egendefinerte roller kan ikke få roles.manage. Det beskytter administrasjon av roller mot eskalering.</p></section><section class="form-card"><h2>Opprett rolle</h2><form method="post" action="/admin/roles">${csrf(req)}<label>Rollenavn<input name="name" required maxlength="32" pattern="[a-z][a-z0-9_-]*"></label><fieldset><legend>Tillatelser</legend>${permissionInputs}</fieldset><button class="button">Opprett rolle</button></form></section><section class="table-card"><div class="table-scroll"><table><thead><tr><th>Rolle</th><th>Type</th><th>Tillatelser</th><th>Brukere</th></tr></thead><tbody>${roleRows}</tbody></table></div></section>`));
  });

  app.post('/admin/roles', requireAdmin, requirePermission('roles.manage'), (req, res) => {
    const name = String(req.body.name || '').trim().toLowerCase();
    const submitted = Array.isArray(req.body.permissions) ? req.body.permissions : (req.body.permissions ? [req.body.permissions] : []);
    const permissions = [...new Set(submitted.map(String))];
    if (!/^[a-z][a-z0-9_-]{1,31}$/.test(name) || ['admin', 'moderator', 'support', 'user'].includes(name) || permissions.some((permission) => !PERMISSIONS.includes(permission) || permission === 'roles.manage')) {
      return res.status(400).send('Ugyldig rollenavn eller tillatelse.');
    }
    try {
      db.prepare('INSERT INTO admin_roles (name, permissions_json, is_builtin) VALUES (?, ?, 0)')
        .run(name, JSON.stringify(permissions));
    } catch (error) {
      if (String(error.code).includes('SQLITE_CONSTRAINT')) return res.status(409).send('Rollen finnes allerede.');
      throw error;
    }
    record(req, 'role.create', null, { name, permissions });
    res.redirect('/admin/roles');
  });

  app.get('/admin/orders', requireAdmin, requirePermission('orders.read'), (req, res) => {
    res.set('Cache-Control', 'no-store');
    const orders = db.prepare(`SELECT o.id, o.user_id, u.email, o.plan_id, o.period, o.amount_nok, o.payment_method, o.payment_status, o.created_at
      FROM orders o JOIN users u ON u.id = o.user_id ORDER BY o.id DESC LIMIT 200`).all();
    const rows = orders.map((o) => `<tr><td>${o.id}</td><td>${escapeHtml(o.email)}</td><td>${escapeHtml(o.plan_id)} (${escapeHtml(o.period)})</td><td>${o.amount_nok} NOK</td><td>${escapeHtml(o.payment_method)}</td><td>${escapeHtml(o.payment_status)}</td><td>${escapeHtml(o.created_at)}</td></tr>`).join('');
    res.send(page(req, 'Bestillinger', `<section class="page-heading"><h1>Bestillinger</h1></section><section class="table-card"><div class="table-scroll"><table><thead><tr><th>ID</th><th>Kunde</th><th>Plan</th><th>Beløp</th><th>Betaling</th><th>Status</th><th>Opprettet</th></tr></thead><tbody>${rows || '<tr><td colspan="7">Ingen bestillinger.</td></tr>'}</tbody></table></div></section>`));
  });

  app.get('/admin/activity', requireAdmin, requirePermission('activity.read'), (req, res) => {
    res.set('Cache-Control', 'no-store');
    const events = db.prepare(`SELECT a.id, a.action, a.actor_user_id, actor.email AS actor_email,
      a.target_user_id, a.details_json, a.ip_address, a.created_at
      FROM admin_audit_log a LEFT JOIN users actor ON actor.id = a.actor_user_id
      ORDER BY a.id DESC LIMIT 200`).all();
    const rows = events.map((event) => `<tr><td>${escapeHtml(event.created_at)}</td><td>${escapeHtml(event.action)}</td><td>${escapeHtml(event.actor_email || event.actor_user_id || '')}</td><td>${escapeHtml(event.target_user_id || '')}</td><td>${escapeHtml(event.ip_address || '')}</td><td>${escapeHtml(event.details_json)}</td></tr>`).join('');
    res.send(page(req, 'Aktivitetslogg', `<section class="page-heading"><h1>Adminaktivitetslogg</h1><p>Tilgangen er begrenset til roller med activity.read. Fastsett lagringstid og informer brukerne om IP-loggføring.</p></section><section class="table-card"><div class="table-scroll"><table><thead><tr><th>Tid</th><th>Handling</th><th>Admin</th><th>Bruker-ID</th><th>IP</th><th>Detaljer</th></tr></thead><tbody>${rows || '<tr><td colspan="6">Ingen hendelser.</td></tr>'}</tbody></table></div></section>`));
  });
}

module.exports = { installAdminPanel, PERMISSIONS, BUILTIN_ROLES };
