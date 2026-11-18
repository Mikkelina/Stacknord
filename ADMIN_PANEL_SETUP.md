# StackNord Admin Foundation

This change adds an admin panel module and a one-time bootstrap command. It does not replace the existing storefront or payment flows.

## Integration status

The admin module must be mounted by the application after session and CSRF middleware and before the final 404 handler. **The current change has not yet been integrated into `server.js`, so `/admin` is not active until that integration is made and tested. Do not deploy this as a completed admin panel.** Existing `/login`, registration, and order routes also need a follow-up change to reject banned accounts; this is not yet enforced across the storefront.

When integrated, the server should import `installAdminPanel` and call `installAdminPanel(app, db, { csrf, page })` after those helpers are defined. Do not mount it before sessions and CSRF middleware.

## Bootstrap the first administrator

1. Create your own account through the normal registration page.
2. Back up `data/stacknord.sqlite` first.
3. Set `ADMIN_EMAIL` to that account's email in the server environment (or private `.env`), then run once from the project directory:
   ```bash
   ADMIN_EMAIL=you@example.com node scripts/promote-admin.js
   ```
   In PowerShell, set `$env:ADMIN_EMAIL='you@example.com'` and then run `node scripts/promote-admin.js`.
4. Remove `ADMIN_EMAIL` after bootstrapping. The command only promotes an existing account; it does not create a default password or expose one.
5. Sign in at `/admin/login` using that account's existing credentials. Use a unique strong password and enable MFA at the hosting/control-panel level until application MFA is implemented.

Do not commit `.env`, passwords, session secrets, Stripe keys, database files, or backups. Restrict filesystem permissions on the SQLite database and its `-wal`/`-shm` files.

## Module capabilities (once integrated)

- Separate `/admin/login` gate, session ID regeneration, an eight-hour admin session limit, and basic per-IP login throttling.
- Built-in `admin`, `moderator`, and `support` roles with server-side permissions.
- Admin overview, user/order lists, user creation, permanent ban/unban, staff role assignment, custom limited roles, and an admin audit log.
- Custom roles cannot receive `roles.manage`; only the built-in admin role can manage roles.
- The last active administrator cannot be banned or demoted through the panel, and staff cannot ban themselves or other staff unless they have role-management authority.
- IP addresses are stored for admin login/logout and admin actions and visible only to `activity.read`. Establish and implement an appropriate retention period and privacy notice before production use.

This remains a foundation rather than a production security review. Storefront ban enforcement, MFA, full audit event coverage, explicit CSRF/XSS/security tests, log retention automation, product/facturation tools, and deployment validation remain to be implemented. SQLite is the application's file-based database; no aaPanel database credentials are required for this stage.
