require('dotenv').config();

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const Stripe = require('stripe');
const helmet = require('helmet');

if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
  throw new Error('SESSION_SECRET must be set in production.');
}

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === 'production';
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;
const baseUrl = (process.env.APP_URL || '').replace(/\/$/, '');

const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'stacknord.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    plan_id TEXT NOT NULL,
    period TEXT NOT NULL CHECK(period IN ('monthly', 'yearly')),
    amount_nok INTEGER NOT NULL,
    payment_method TEXT NOT NULL,
    payment_status TEXT NOT NULL DEFAULT 'Venter på betaling',
    stripe_session_id TEXT UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
`);

class SQLiteSessionStore extends session.Store {
  constructor(database) {
    super();
    this.db = database;
    this.getStmt = database.prepare('SELECT data, expires_at FROM sessions WHERE sid = ?');
    this.setStmt = database.prepare(`INSERT INTO sessions (sid, data, expires_at) VALUES (?, ?, ?)
      ON CONFLICT(sid) DO UPDATE SET data = excluded.data, expires_at = excluded.expires_at`);
    this.touchStmt = database.prepare('UPDATE sessions SET expires_at = ? WHERE sid = ?');
    this.destroyStmt = database.prepare('DELETE FROM sessions WHERE sid = ?');
    this.pruneStmt = database.prepare('DELETE FROM sessions WHERE expires_at <= ?');
    this.timer = setInterval(() => this.pruneStmt.run(Date.now()), 60 * 60 * 1000);
    this.timer.unref();
  }
  get(sid, callback) {
    try {
      const row = this.getStmt.get(sid);
      if (!row || row.expires_at <= Date.now()) {
        if (row) this.destroyStmt.run(sid);
        return callback(null, null);
      }
      callback(null, JSON.parse(row.data));
    } catch (error) { callback(error); }
  }
  set(sid, sess, callback = () => {}) {
    try {
      const expiresAt = sess.cookie?.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 7 * 86400000;
      this.setStmt.run(sid, JSON.stringify(sess), expiresAt);
      callback(null);
    } catch (error) { callback(error); }
  }
  touch(sid, sess, callback = () => {}) {
    try {
      const expiresAt = sess.cookie?.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 7 * 86400000;
      this.touchStmt.run(expiresAt, sid);
      callback(null);
    } catch (error) { callback(error); }
  }
  destroy(sid, callback = () => {}) {
    try { this.destroyStmt.run(sid); callback(null); }
    catch (error) { callback(error); }
  }
}

const plans = {
  start: { name: 'Start', nok: 49, usd: 4.9, storage: '10 GB SSD', domains: '1 domene', ssl: 'Gratis SSL' },
  pro: { name: 'Pro', nok: 99, usd: 9.9, storage: '50 GB SSD', domains: '5 domener', ssl: 'Gratis SSL' },
  node: { name: 'Node.js App', nok: 149, usd: 14.9, storage: '100 GB SSD', domains: '10 domener', ssl: 'Gratis SSL' }
};
const nordicCountries = new Set(['NO', 'SE', 'DK', 'FI', 'IS']);
const allowedPayments = new Set(['stripe', 'paypal', 'crypto', 'vipps']);

app.set('trust proxy', 1);
app.use(helmet());
// Stripe signature validation requires the raw request body, before JSON parsing.
app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), (req, res) => {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) return res.status(503).send('Stripe webhook is not configured.');
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (error) {
    return res.status(400).send(`Invalid webhook signature: ${error.message}`);
  }
  if (event.type === 'checkout.session.completed') {
    const checkout = event.data.object;
    if (checkout.payment_status === 'paid' && checkout.metadata?.orderId) {
      db.prepare(`UPDATE orders SET payment_status = 'Betalt' WHERE id = ? AND stripe_session_id = ?`)
        .run(Number(checkout.metadata.orderId), checkout.id);
    }
  }
  res.json({ received: true });
});
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(express.json({ limit: '20kb' }));
app.use(session({
  name: 'stacknord.sid',
  store: new SQLiteSessionStore(db),
  secret: process.env.SESSION_SECRET || 'development-only-secret-change-this',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: isProduction, httpOnly: true, sameSite: 'lax', maxAge: 7 * 86400000 }
}));
app.use((req, res, next) => {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  if (req.method === 'POST') {
    const submitted = String(req.body?._csrf || '');
    const expected = req.session.csrfToken;
    if (submitted.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(submitted), Buffer.from(expected))) {
      return res.status(403).send(page(req, 'Ugyldig forespørsel', '<div class="notice notice-error">Skjemaet er utløpt. Last siden på nytt og prøv igjen.</div>'));
    }
  }
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

function escapeHtml(value = '') {
  return String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}
function formatNok(value) {
  return new Intl.NumberFormat('nb-NO', { style: 'currency', currency: 'NOK', maximumFractionDigits: 0 }).format(value);
}
function csrf(req) { return `<input type="hidden" name="_csrf" value="${escapeHtml(req.session.csrfToken)}">`; }
function page(req, title, content) {
  const user = req.session.user;
  const nav = user
    ? `<a href="/">Forside</a><a href="/dashboard">Min side</a><form class="nav-form" method="post" action="/logout">${csrf(req)}<button class="nav-link">Logg ut</button></form>`
    : `<a href="/">Forside</a><a href="/login">Logg inn</a><a href="/register">Registrer deg</a>`;
  return `<!doctype html><html lang="no"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)} | StackNord</title><link rel="stylesheet" href="/style.css"></head><body><header class="site-header"><div class="container nav-wrap"><a href="/" class="brand">Stack<span>Nord</span></a><nav class="main-nav">${nav}</nav></div></header><main class="container">${content}</main><footer class="site-footer">© ${new Date().getFullYear()} StackNord</footer></body></html>`;
}
function requireAuth(req, res, next) { if (!req.session.user) return res.redirect('/login'); next(); }
function planCard(id, p) {
  return `<article class="plan-card ${id === 'pro' ? 'featured' : ''}">${id === 'pro' ? '<span class="badge">Mest populær</span>' : ''}<h3>${escapeHtml(p.name)}</h3><div class="price">${p.nok} kr <small>/ mnd</small></div><div class="muted">ca. $${p.usd.toFixed(2)} USD / mnd</div><ul class="feature-list"><li>${escapeHtml(p.storage)}</li><li>${escapeHtml(p.domains)}</li><li>${escapeHtml(p.ssl)}</li></ul><a class="button" href="/checkout?plan=${id}">Bestill nå</a></article>`;
}
function checkoutContent(req, planId, period, message = '') {
  const p = plans[planId];
  const total = p.nok * (period === 'yearly' ? 10 : 1);
  return `${message}<section class="page-head"><div class="eyebrow">SIKKER BESTILLING</div><h1>Kasse</h1><div class="stepper"><span class="step done">1. Valgt pakke</span><i></i><span class="step current">2. Kontoinformasjon</span><i></i><span class="step">3. Betaling</span></div></section><form method="post" action="/checkout"><input type="hidden" name="_csrf" value="${escapeHtml(req.session.csrfToken)}"><input type="hidden" name="plan" value="${escapeHtml(planId)}"><input type="hidden" name="period" value="${period}"><div class="checkout-grid"><section class="checkout-card"><h2>${req.session.user ? 'Kontoinformasjon' : 'Opprett konto'}</h2>${req.session.user ? `<p>Bestillingen knyttes til <b>${escapeHtml(req.session.user.email)}</b>.</p>` : `<label>Navn<input name="name" required maxlength="100" autocomplete="name"></label><label>E-post<input name="email" type="email" required maxlength="254" autocomplete="email"></label><label>Passord<input name="password" type="password" required minlength="8" maxlength="200" autocomplete="new-password"></label>`}<h2 class="payment-title">Velg betalingsmåte</h2><label class="payment-option"><input type="radio" name="payment" value="stripe" checked><span><b>Kortbetaling</b><small>Visa · Mastercard · Apple Pay (via Stripe der det støttes)</small></span></label><label class="payment-option"><input type="radio" name="payment" value="paypal"><span><b>PayPal</b><small>Betal via PayPal-link</small></span></label><label class="payment-option"><input type="radio" name="payment" value="crypto"><span><b>Krypto</b><small>Bitcoin · USDC · ETH, manuell betaling</small></span></label><label class="payment-option"><input type="radio" name="payment" value="vipps"><span><b>Vipps</b><small>Kun for kunder i Norden</small></span></label><label>Land<select name="country"><option value="NO">Norge</option><option value="SE">Sverige</option><option value="DK">Danmark</option><option value="FI">Finland</option><option value="IS">Island</option><option value="OTHER">Annet</option></select></label><p class="muted small">Manuelle betalingsvalg blir ikke godkjent automatisk.</p><button class="button full-width" type="submit">Fortsett til betaling</button></section><aside class="summary-card"><h2>Ordreoversikt</h2><div class="summary-plan"><span class="plan-icon">S</span><div><b>StackNord ${escapeHtml(p.name)}</b><small>${escapeHtml(p.storage)} · ${escapeHtml(p.domains)} · ${escapeHtml(p.ssl)}</small></div></div><label>Faktureringsperiode<select onchange="location.href='/checkout?plan=${planId}&period='+this.value"><option value="monthly" ${period === 'monthly' ? 'selected' : ''}>Månedlig</option><option value="yearly" ${period === 'yearly' ? 'selected' : ''}>Årlig (betal for 10 måneder)</option></select></label><div class="summary-line"><span>Pakke</span><b>${formatNok(total)}</b></div><div class="summary-line"><span>SSL</span><b>Inkludert</b></div><div class="summary-total"><span>Sum</span><b>${formatNok(total)}${period === 'monthly' ? ' / mnd' : ' / år'}</b></div><p class="muted small">Hostingkonto blir ikke opprettet automatisk av denne versjonen.</p></aside></div></form>`;
}

app.get('/', (req, res) => res.send(page(req, 'Webhotell', `<section class="hero"><div><div class="eyebrow">WEBHOTELL · NORDISK ENKELHET</div><h1>Plass til idéene dine.<br><span>Bygget for å vokse.</span></h1><p class="lead">Moderne webhotell for nettsteder og apper, med tydelige pakker og enkel bestilling.</p><a href="#pakker" class="button">Se pakkene</a></div><div class="hero-visual"><div class="mini-panel">stacknord.app <b class="online-dot">● Online</b></div><div class="mini-graph"><span></span><span></span><span></span></div></div></section><section id="pakker" class="plans-section"><div class="section-head"><div class="eyebrow">VELG DIN PAKKE</div><h2>Rett pakke for prosjektet ditt</h2></div><div class="plans-grid">${Object.entries(plans).map(([id, p]) => planCard(id, p)).join('')}</div></section><section class="trust-row"><div><b>Gratis SSL</b><span>Sikker tilkobling inkludert</span></div><div><b>Enkel bestilling</b><span>Tydelige pakker og priser</span></div><div><b>Ingen skjulte priser</b><span>Se kostnaden før bestilling</span></div></section>`)));

app.get('/register', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.send(page(req, 'Registrer deg', `<section class="form-card narrow-card"><div class="eyebrow">KOM I GANG</div><h1>Opprett konto</h1><form method="post" action="/register">${csrf(req)}<label>Navn<input name="name" required maxlength="100" autocomplete="name"></label><label>E-post<input type="email" name="email" required maxlength="254" autocomplete="email"></label><label>Passord<input type="password" name="password" required minlength="8" maxlength="200" autocomplete="new-password"></label><button class="button full-width">Opprett konto</button></form><p>Har du konto? <a href="/login">Logg inn</a></p></section>`));
});
app.post('/register', async (req, res) => {
  const name = String(req.body.name || '').trim(); const email = String(req.body.email || '').trim().toLowerCase(); const password = String(req.body.password || '');
  if (!name || name.length > 100 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 || password.length < 8 || password.length > 200) return res.status(400).send(page(req, 'Registrer deg', '<div class="notice notice-error">Sjekk navn, e-post og passord (minst 8 tegn).</div>'));
  try {
    const hash = await bcrypt.hash(password, 12); const result = db.prepare('INSERT INTO users (name,email,password_hash) VALUES (?,?,?)').run(name,email,hash);
    req.session.regenerate((error) => { if (error) return res.status(500).send('Kunne ikke starte økten.'); req.session.user = { id: Number(result.lastInsertRowid), name, email }; req.session.csrfToken = crypto.randomBytes(32).toString('hex'); res.redirect('/dashboard'); });
  } catch (error) { if (String(error.code).includes('SQLITE_CONSTRAINT')) return res.status(409).send(page(req, 'Registrer deg', '<div class="notice notice-error">E-postadressen er allerede registrert.</div>')); console.error(error); res.status(500).send('Kunne ikke opprette konto.'); }
});
app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.send(page(req, 'Logg inn', `<section class="form-card narrow-card"><div class="eyebrow">VELKOMMEN TILBAKE</div><h1>Logg inn</h1><form method="post" action="/login">${csrf(req)}<label>E-post<input type="email" name="email" required autocomplete="email"></label><label>Passord<input type="password" name="password" required autocomplete="current-password"></label><button class="button full-width">Logg inn</button></form><p>Ny hos StackNord? <a href="/register">Opprett konto</a></p></section>`));
});
app.post('/login', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(); const password = String(req.body.password || ''); const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).send(page(req, 'Logg inn', '<div class="notice notice-error">E-post eller passord stemmer ikke.</div>'));
  req.session.regenerate((error) => { if (error) return res.status(500).send('Kunne ikke starte økten.'); req.session.user = { id: user.id, name: user.name, email: user.email }; req.session.csrfToken = crypto.randomBytes(32).toString('hex'); res.redirect('/dashboard'); });
});
app.post('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

app.get('/dashboard', requireAuth, (req, res) => {
  const orders = db.prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC').all(req.session.user.id);
  const rows = orders.length ? orders.map((o) => `<tr><td><b>${escapeHtml(plans[o.plan_id]?.name || o.plan_id)}</b><small>${o.period === 'yearly' ? 'Årlig' : 'Månedlig'}</small></td><td>${formatNok(o.amount_nok)}</td><td><span class="status">${escapeHtml(o.payment_status)}</span></td><td><a href="/orders/${o.id}">Vis ordre</a></td></tr>`).join('') : '<tr><td colspan="4" class="empty">Du har ingen bestillinger ennå.</td></tr>';
  res.send(page(req, 'Min side', `<section class="page-heading"><div class="eyebrow">KUNDEOMRÅDE</div><h1>Hei, ${escapeHtml(req.session.user.name)}</h1><p>Her finner du bestillinger og betalingsstatus.</p></section><section class="table-card"><div class="table-heading"><h2>Bestillingene dine</h2><a class="button" href="/#pakker">Bestill ny pakke</a></div><div class="table-scroll"><table><thead><tr><th>Pakke</th><th>Sum</th><th>Status</th><th></th></tr></thead><tbody>${rows}</tbody></table></div></section>`));
});

app.get('/checkout', (req, res) => {
  const planId = String(req.query.plan || 'start'); const period = req.query.period === 'yearly' ? 'yearly' : 'monthly';
  if (!plans[planId]) return res.redirect('/#pakker');
  res.send(page(req, 'Kasse', checkoutContent(req, planId, period)));
});
app.post('/checkout', async (req, res) => {
  const planId = String(req.body.plan || ''); const period = req.body.period === 'yearly' ? 'yearly' : 'monthly'; const method = String(req.body.payment || ''); const country = String(req.body.country || ''); const plan = plans[planId];
  if (!plan || !allowedPayments.has(method)) return res.status(400).send(page(req, 'Kasse', '<div class="notice notice-error">Ugyldig pakke eller betalingsmåte.</div>'));
  if (method === 'vipps' && !nordicCountries.has(country)) return res.status(400).send(page(req, 'Kasse', checkoutContent(req, planId, period, '<div class="notice notice-error">Vipps er bare tilgjengelig for kunder i Norden.</div>')));
  let user = req.session.user;
  if (!user) {
    const name = String(req.body.name || '').trim(); const email = String(req.body.email || '').trim().toLowerCase(); const password = String(req.body.password || '');
    if (!name || name.length > 100 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 || password.length < 8 || password.length > 200) return res.status(400).send(page(req, 'Kasse', checkoutContent(req, planId, period, '<div class="notice notice-error">Fyll inn gyldig navn/e-post og passord på minst 8 tegn.</div>')));
    try { const hash = await bcrypt.hash(password, 12); const result = db.prepare('INSERT INTO users (name,email,password_hash) VALUES (?,?,?)').run(name,email,hash); user = { id: Number(result.lastInsertRowid), name, email }; req.session.user = user; }
    catch (error) { if (String(error.code).includes('SQLITE_CONSTRAINT')) return res.status(409).send(page(req, 'Kasse', checkoutContent(req, planId, period, '<div class="notice notice-error">E-posten er allerede registrert. Logg inn først.</div>'))); throw error; }
  }
  const amount = plan.nok * (period === 'yearly' ? 10 : 1);
  const result = db.prepare('INSERT INTO orders (user_id,plan_id,period,amount_nok,payment_method,payment_status) VALUES (?,?,?,?,?,?)').run(user.id,planId,period,amount,method,'Venter på betaling');
  res.redirect(`/orders/${result.lastInsertRowid}`);
});

app.get('/orders/:id', requireAuth, (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?').get(Number(req.params.id), req.session.user.id);
  if (!order) return res.status(404).send(page(req, 'Ordre ikke funnet', '<h1>Ordre ikke funnet</h1>'));
  const plan = plans[order.plan_id]; let instructions = '';
  if (order.payment_method === 'stripe') instructions = stripe ? `<form method="post" action="/pay/stripe/${order.id}">${csrf(req)}<button class="button">Betal med kort</button></form>` : '<div class="notice">Stripe er ikke konfigurert.</div>';
  if (order.payment_method === 'paypal') instructions = process.env.PAYPAL_ME_LINK ? `<p>Betal via PayPal. Ordren må kontrolleres manuelt.</p><a class="button" target="_blank" rel="noopener noreferrer" href="${escapeHtml(process.env.PAYPAL_ME_LINK)}">Åpne PayPal</a>` : '<div class="notice">PAYPAL_ME_LINK er ikke konfigurert.</div>';
  if (order.payment_method === 'crypto') instructions = process.env.CRYPTO_WALLET ? `<p>Send betaling og oppgi ordrenummer SN-${order.id}. Betalingen kontrolleres manuelt.</p><code class="wallet">${escapeHtml(process.env.CRYPTO_WALLET)}</code>` : '<div class="notice">CRYPTO_WALLET er ikke konfigurert.</div>';
  if (order.payment_method === 'vipps') instructions = process.env.VIPPS_NUMBER ? `<p>Vipps til <b>${escapeHtml(process.env.VIPPS_NUMBER)}</b>. Skriv <b>SN-${order.id}</b> i meldingsfeltet.</p><form method="post" action="/orders/${order.id}/vipps-confirm">${csrf(req)}<button class="button">Jeg har vippset</button></form>` : '<div class="notice">VIPPS_NUMBER er ikke konfigurert.</div>';
  res.send(page(req, `Ordre SN-${order.id}`, `<section class="page-heading"><div class="eyebrow">ORDRE SN-${order.id}</div><h1>Takk for bestillingen</h1><p>Status: <span class="status">${escapeHtml(order.payment_status)}</span></p></section><div class="checkout-grid"><section class="checkout-card"><h2>Betaling</h2>${instructions}<p class="muted small">Manuelle betalinger må kontrolleres før ordren markeres betalt.</p></section><aside class="summary-card"><h2>Ordreoversikt</h2><b>StackNord ${escapeHtml(plan.name)}</b><p>${escapeHtml(plan.storage)} · ${escapeHtml(plan.domains)} · ${escapeHtml(plan.ssl)}</p><p>${order.period === 'yearly' ? 'Årlig' : 'Månedlig'}</p><div class="summary-total"><span>Sum</span><b>${formatNok(order.amount_nok)}</b></div><a href="/dashboard">Min side</a></aside></div>`));
});
app.post('/orders/:id/vipps-confirm', requireAuth, (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?').get(Number(req.params.id), req.session.user.id);
  if (!order || order.payment_method !== 'vipps') return res.status(404).send(page(req, 'Ordre ikke funnet', '<h1>Ordre ikke funnet</h1>'));
  db.prepare("UPDATE orders SET payment_status = 'Til godkjenning' WHERE id = ? AND payment_status = 'Venter på betaling'").run(order.id);
  res.redirect(`/orders/${order.id}`);
});

app.post('/pay/stripe/:id', requireAuth, async (req, res) => {
  if (!stripe) return res.status(503).send(page(req, 'Betaling', '<div class="notice">Stripe er ikke konfigurert.</div>'));
  if (!baseUrl || !/^https:\/\//i.test(baseUrl)) return res.status(503).send(page(req, 'Betaling', '<div class="notice">Sett APP_URL til nettstedets offentlige HTTPS-adresse før Stripe aktiveres.</div>'));
  const order = db.prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?').get(Number(req.params.id), req.session.user.id);
  if (!order || order.payment_status !== 'Venter på betaling') return res.status(404).send('Ordre finnes ikke eller er ikke betalbar.');
  const plan = plans[order.plan_id];
  try {
    const checkout = await stripe.checkout.sessions.create({
      mode: 'payment',
      managed_payments: { enabled: false },
      customer_email: req.session.user.email,
      line_items: [{ quantity: 1, price_data: { currency: 'nok', unit_amount: order.amount_nok * 100, product_data: { name: `StackNord ${plan.name}`, description: order.period === 'yearly' ? 'Årlig webhotell' : 'Månedlig webhotell' } } }],
      metadata: { orderId: String(order.id) },
      success_url: `${baseUrl}/orders/${order.id}?payment=success`,
      cancel_url: `${baseUrl}/orders/${order.id}?payment=cancelled`
    });
    db.prepare('UPDATE orders SET stripe_session_id = ? WHERE id = ?').run(checkout.id, order.id);
    res.redirect(303, checkout.url);
  } catch (error) { console.error('Stripe checkout error:', error.message); res.status(502).send(page(req, 'Betaling', '<div class="notice notice-error">Kunne ikke starte Stripe-betalingen. Prøv igjen senere.</div>')); }
});

app.use((req, res) => res.status(404).send(page(req, 'Siden finnes ikke', '<section class="form-card"><h1>Siden finnes ikke</h1><a href="/">Til forsiden</a></section>')));
app.listen(PORT, '0.0.0.0', () => console.log(`StackNord listening on port ${PORT}`));
