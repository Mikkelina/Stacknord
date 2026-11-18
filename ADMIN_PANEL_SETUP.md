# StackNord Admin Foundation

This change adds an admin panel module and a one-time bootstrap command. It does not replace the existing storefront or payment flows.

## Important: integrate the module into `server.js`

The repository's `server.js` currently does not load admin routes. Before deploying this feature, wire it into the Express application:

1. Near the existing `require(...)` statements, add:
   ```js
   const { installAdminPanel } = require('./admin-panel');
   ```
2. After the existing `page()` and `csrf()` helpers are defined, and after the session/CSRF middleware is installed, add:
   ```js
   installAdminPanel(app, db, { csrf, page });
   ```
   It must be before the final catch-all 404 handler.

The existing middleware applies CSRF validation to POST routes, including the admin forms. Do not mount admin routes before sessions and CSRF middleware.

## Bootstrap the first administrator

1. Create your own account through the normal registration page.
2. Back up `data/stacknord.sqlite` first.
3. Set `ADMIN_EMAIL` to that account's email in the server environment (or the private `.env` file), then run once from the project directory:
   ```bash
   ADMIN_EMAIL=you@example.com node scripts/promote-admin.js
   ```
   On Windows PowerShell, set `$env:ADMIN_EMAIL='you@example.com'` and then run `node scripts/promote-admin.js`.
4. Remove `ADMIN_EMAIL` after bootstrapping. The command only promotes an existing account; it does not create a default password or expose one.
5. Sign in at `/admin/login` using that account's existing credentials. Enable MFA at the hosting/control-panel account level and use a unique strong password.

Do not commit `.env`, passwords, session secrets, Stripe keys, database files, or backups. Restrict filesystem permissions on the SQLite database and its `-wal`/`-shm` files.

## Initial capabilities

- Separate `/admin/login` gate and session-regeneration on successful admin login.
- Built-in `admin`, `moderator`, and `support` roles with server-side permissions.
- Admin overview, user/order lists, user creation, permanent ban/unban, and an admin audit log.
- Sensitive ban and role-changing actions are not exposed as customer-facing routes. Admin actions use CSRF protection from the host application.
- The last active administrator cannot be banned through this panel.
- IP addresses are stored for admin login/logout and admin actions and visible only to the `activity.read` permission. Establish an appropriate retention period and privacy notice before production use.

This is a foundation, not a complete security/compliance review. Before production, add rate limiting and MFA for staff, define audit/IP retention, test backups and restoration, review account recovery, and validate deployment behind HTTPS with correct proxy settings. Product catalog, Stripe invoicing, custom-role UI, staff invitations, support tickets, and fine-grained order moderation are not implemented in this initial foundation.
