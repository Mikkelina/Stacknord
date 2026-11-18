'use strict';

function escapeHtml(value = '') {
  return String(value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[char]));
}

function installAdminExtras(app, db, { csrf, page }) {
  if (typeof csrf !== 'function' || typeof page !== 'function') throw new Error('Admin extras require csrf() and page().');
  db.exec(`
    CREATE TABLE IF NOT EXISTS support_tickets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id),
      subject TEXT NOT NULL,
      message TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','in_progress','closed')),
      staff_reply TEXT,
      handled_by INTEGER REFERENCES users(id),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_support_tickets_user ON support_tickets(user_id, id DESC);
    CREATE INDEX IF NOT EXISTS idx_support_tickets_status ON support_tickets(status, id DESC);
  `);

  // Keep the audit trail for a finite, configurable period. Default: 90 days.
  const configuredRetention = Number(process.env.ADMIN_AUDIT_RETENTION_DAYS || 90);
  const retentionDays = Number.isInteger(configuredRetention) && configuredRetention >= 30 && configuredRetention <= 3650
    ? configuredRetention : 90;
  const pruneAudit = db.prepare("DELETE FROM admin_audit_log WHERE created_at < datetime('now', ?)");
  const pruneAttempts = db.prepare('DELETE FROM admin_login_attempts WHERE attempted_at < ?');
  const prune = () => {
    pruneAudit.run(`-${retentionDays} days`);
    pruneAttempts.run(Date.now() - 24 * 60 * 60 * 1000);
  };
  prune();
  const retentionTimer = setInterval(prune, 24 * 60 * 60 * 1000);
  retentionTimer.unref();

  function requireUser(req, res, next) {
    if (!req.session?.user) return res.redirect('/login');
    next();
  }
  function requireStaff(permission = 'users.read') {
    return (req, res, next) => {
      if (!req.session?.user || !req.session.adminAuthenticatedAt || Date.now() - Number(req.session.adminAuthenticatedAt) > 8 * 60 * 60 * 1000) {
        return res.redirect('/admin/login');
      }
      const user = db.prepare('SELECT id, role, account_status FROM users WHERE id = ?').get(req.session.user.id);
      if (!user || user.account_status !== 'active') return res.redirect('/admin/login');
      const roleRow = db.prepare('SELECT permissions_json FROM admin_roles WHERE name = ?').get(user.role);
      let permissions = [];
      try { permissions = JSON.parse(roleRow?.permissions_json || '[]'); } catch { permissions = []; }
      if (!Array.isArray(permissions) || !permissions.includes(permission)) {
        return res.status(403).send(page(req, 'Ingen tilgang', '<section class="form-card"><h1>Ingen tilgang</h1></section>'));
      }
      req.staffUser = user;
      next();
    };
  }
  function audit(req, action, targetUserId, extra = {}) {
    db.prepare(`INSERT INTO admin_audit_log (actor_user_id, action, target_user_id, details_json, ip_address)
      VALUES (?, ?, ?, ?, ?)`).run(
      req.staffUser.id, action, targetUserId || null, JSON.stringify(extra).slice(0, 2000),
      String(req.ip || req.socket?.remoteAddress || '').slice(0, 64) || null
    );
  }

  app.get('/support', requireUser, (req, res) => {
    res.set('Cache-Control', 'no-store');
    const tickets = db.prepare('SELECT id, subject, status, created_at, updated_at FROM support_tickets WHERE user_id = ? ORDER BY id DESC LIMIT 100')
      .all(req.session.user.id);
    const rows = tickets.map((ticket) => `<tr><td><a href="/support/${ticket.id}">#${ticket.id} — ${escapeHtml(ticket.subject)}</a></td><td>${escapeHtml(ticket.status)}</td><td>${escapeHtml(ticket.updated_at)}</td></tr>`).join('');
    res.send(page(req, 'Kundestøtte', `<section class="page-heading"><h1>Kundestøtte</h1><p>Send en henvendelse eller se svar på sakene dine.</p></section><section class="form-card"><form method="post" action="/support">${csrf(req)}<label>Emne<input name="subject" required maxlength="120"></label><label>Melding<textarea name="message" required minlength="10" maxlength="5000"></textarea></label><button class="button">Send henvendelse</button></form></section><section class="table-card"><h2>Mine saker</h2><table><thead><tr><th>Sak</th><th>Status</th><th>Sist oppdatert</th></tr></thead><tbody>${rows || '<tr><td colspan="3">Ingen saker ennå.</td></tr>'}</tbody></table></section>`));
  });

  app.post('/support', requireUser, (req, res) => {
    const subject = String(req.body.subject || '').trim();
    const message = String(req.body.message || '').trim();
    if (subject.length < 3 || subject.length > 120 || message.length < 10 || message.length > 5000) {
      return res.status(400).send(page(req, 'Kundestøtte', '<div class="notice notice-error">Kontroller emne og melding. Meldingen må være 10–5000 tegn.</div><a href="/support">Tilbake</a>'));
    }
    const result = db.prepare('INSERT INTO support_tickets (user_id, subject, message) VALUES (?, ?, ?)')
      .run(req.session.user.id, subject, message);
    res.redirect(`/support/${Number(result.lastInsertRowid)}`);
  });

  app.get('/support/:id', requireUser, (req, res) => {
    const ticket = db.prepare('SELECT id, subject, message, status, staff_reply, created_at, updated_at FROM support_tickets WHERE id = ? AND user_id = ?')
      .get(Number(req.params.id), req.session.user.id);
    if (!ticket) return res.status(404).send(page(req, 'Sak ikke funnet', '<h1>Sak ikke funnet</h1>'));
    res.set('Cache-Control', 'no-store');
    res.send(page(req, `Support #${ticket.id}`, `<section class="page-heading"><div class="eyebrow">SAK #${ticket.id}</div><h1>${escapeHtml(ticket.subject)}</h1><p>Status: ${escapeHtml(ticket.status)} · Opprettet ${escapeHtml(ticket.created_at)}</p></section><section class="table-card"><h2>Din melding</h2><p>${escapeHtml(ticket.message).replace(/\n/g, '<br>')}</p>${ticket.staff_reply ? `<h2>Svar fra support</h2><p>${escapeHtml(ticket.staff_reply).replace(/\n/g, '<br>')}</p>` : '<p>Vi har ikke svart ennå.</p>'}<a href="/support">Alle mine saker</a></section>`));
  });

  app.get('/admin/support', requireStaff('users.read'), (req, res) => {
    res.set('Cache-Control', 'no-store');
    const tickets = db.prepare(`SELECT t.id, t.subject, t.status, t.updated_at, u.email
      FROM support_tickets t JOIN users u ON u.id = t.user_id ORDER BY
      CASE t.status WHEN 'open' THEN 0 WHEN 'in_progress' THEN 1 ELSE 2 END, t.id DESC LIMIT 200`).all();
    const rows = tickets.map((ticket) => `<tr><td><a href="/admin/support/${ticket.id}">#${ticket.id} — ${escapeHtml(ticket.subject)}</a></td><td>${escapeHtml(ticket.email)}</td><td>${escapeHtml(ticket.status)}</td><td>${escapeHtml(ticket.updated_at)}</td></tr>`).join('');
    res.send(page(req, 'Supporthenvendelser', `<section class="page-heading"><h1>Supporthenvendelser</h1><p>Viser inntil 200 saker. Behandle kundedata konfidensielt.</p></section><section class="table-card"><table><thead><tr><th>Sak</th><th>Kunde</th><th>Status</th><th>Oppdatert</th></tr></thead><tbody>${rows || '<tr><td colspan="4">Ingen saker.</td></tr>'}</tbody></table></section>`));
  });

  app.get('/admin/support/:id', requireStaff('users.read'), (req, res) => {
    const ticket = db.prepare('SELECT t.*, u.email FROM support_tickets t JOIN users u ON u.id = t.user_id WHERE t.id = ?')
      .get(Number(req.params.id));
    if (!ticket) return res.status(404).send(page(req, 'Sak ikke funnet', '<h1>Sak ikke funnet</h1>'));
    res.set('Cache-Control', 'no-store');
    res.send(page(req, `Support #${ticket.id}`, `<section class="page-heading"><h1>#${ticket.id}: ${escapeHtml(ticket.subject)}</h1><p>Kunde: ${escapeHtml(ticket.email)} · Status: ${escapeHtml(ticket.status)}</p></section><section class="table-card"><h2>Kundens melding</h2><p>${escapeHtml(ticket.message).replace(/\n/g, '<br>')}</p><form method="post" action="/admin/support/${ticket.id}">${csrf(req)}<label>Svar<textarea name="reply" maxlength="5000">${escapeHtml(ticket.staff_reply || '')}</textarea></label><label>Status<select name="status"><option value="open" ${ticket.status === 'open' ? 'selected' : ''}>Åpen</option><option value="in_progress" ${ticket.status === 'in_progress' ? 'selected' : ''}>Under behandling</option><option value="closed" ${ticket.status === 'closed' ? 'selected' : ''}>Lukket</option></select></label><button class="button">Lagre svar og status</button></form></section>`));
  });

  app.post('/admin/support/:id', requireStaff('users.read'), (req, res) => {
    const ticketId = Number(req.params.id);
    const reply = String(req.body.reply || '').trim();
    const status = String(req.body.status || '');
    if (!db.prepare('SELECT id FROM support_tickets WHERE id = ?').get(ticketId)) return res.status(404).send('Saken finnes ikke.');
    if (!['open', 'in_progress', 'closed'].includes(status) || reply.length > 5000) return res.status(400).send('Ugyldig svar eller status.');
    db.prepare('UPDATE support_tickets SET staff_reply = ?, status = ?, handled_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(reply || null, status, req.staffUser.id, ticketId);
    audit(req, 'support_ticket.update', ticketId, { status });
    res.redirect(`/admin/support/${ticketId}`);
  });

  app.get('/admin/orders/:id/review', requireStaff('orders.manage'), (req, res) => {
    const order = db.prepare(`SELECT o.id, u.email, o.payment_method, o.payment_status, o.amount_nok
      FROM orders o JOIN users u ON u.id = o.user_id WHERE o.id = ?`).get(Number(req.params.id));
    if (!order) return res.status(404).send('Ordren finnes ikke.');
    const manual = ['paypal', 'crypto', 'vipps'].includes(order.payment_method);
    const form = manual && order.payment_status !== 'Betalt'
      ? `<form method="post" action="/admin/orders/${order.id}/review">${csrf(req)}<label>Status<select name="status"><option value="Til godkjenning">Til godkjenning</option><option value="Betalt">Betalt (bekreftet manuelt)</option><option value="Avbrutt">Avbrutt</option></select></label><button class="button">Lagre status</button></form>`
      : '<p>Stripe-betalinger bekreftes bare av signert webhook. Refusjon må håndteres i betalingsleverandøren.</p>';
    res.send(page(req, `Ordre ${order.id}`, `<section class="page-heading"><h1>Ordre #${order.id}</h1><p>${escapeHtml(order.email)} · ${order.amount_nok} NOK · ${escapeHtml(order.payment_method)} · ${escapeHtml(order.payment_status)}</p></section><section class="form-card">${form}<a href="/admin/orders">Tilbake til bestillinger</a></section>`));
  });

  app.post('/admin/orders/:id/review', requireStaff('orders.manage'), (req, res) => {
    const orderId = Number(req.params.id);
    const status = String(req.body.status || '');
    if (!['Til godkjenning', 'Betalt', 'Avbrutt'].includes(status)) return res.status(400).send('Ugyldig ordrestatus.');
    const order = db.prepare('SELECT id, payment_method, payment_status FROM orders WHERE id = ?').get(orderId);
    if (!order) return res.status(404).send('Ordren finnes ikke.');
    if (!['paypal', 'crypto', 'vipps'].includes(order.payment_method)) return res.status(403).send('Stripe-status kan ikke endres manuelt.');
    if (order.payment_status === 'Betalt' && status !== 'Betalt') return res.status(409).send('Betalte ordre kan ikke tilbakerulles her.');
    db.prepare('UPDATE orders SET payment_status = ? WHERE id = ?').run(status, orderId);
    audit(req, 'order.manual_status_change', orderId, { from: order.payment_status, to: status, method: order.payment_method });
    res.redirect('/admin/orders');
  });
}

module.exports = { installAdminExtras };
