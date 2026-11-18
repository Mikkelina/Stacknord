# Admin integration runbook

The admin routes and banned-account guard must be integrated into `server.js` before the panel can be used. The integration script is deliberately one-time and idempotent: it checks known source anchors, validates syntax, writes a backup, then replaces `server.js` atomically. If the source layout differs, it stops without modifying the server.

## Apply integration

1. Take a separate backup of the project and `data/stacknord.sqlite` first. Do this while the application is stopped so SQLite WAL data is included safely.
2. From the project root (same directory as `server.js`), run:
   ```bash
   node scripts/integrate-admin.js
   ```
3. Check that a `server.js.pre-admin-*.bak` backup was created, then run:
   ```bash
   node --check server.js
   npm start
   ```
4. Visit `/admin/login`. An existing account has no staff permissions until promoted with the separate `scripts/promote-admin.js` command. Use the bootstrap procedure in `ADMIN_PANEL_SETUP.md`.
5. Test customer login, checkout, Stripe webhook, admin login, user creation, banning/unbanning, role assignment, and CSRF rejection in a non-production copy before deployment.

The script adds the admin route module after the existing helper definitions, before storefront routes, and installs an account-status guard before static files/routes. A banned or disabled account's existing session is destroyed on its next request. Do not remove the guard or mount the admin module before sessions and CSRF middleware.

## Rollback

Stop the app and restore the backup named by the integration script, for example:
```bash
cp server.js.pre-admin-YYYY-MM-DDTHH-MM-SS-sssZ.bak server.js
```
Restore the matching SQLite backup only if a migration has already run and rollback is necessary; the migration is additive, but restoring an older DB discards subsequent data. Never copy a live SQLite database without accounting for its WAL files.

This integration does not make the application production-ready by itself. Rate limiting is basic and in the app database; add proxy/IP verification, MFA, audit retention, monitoring, and security tests before launch. The integration process should be tested on a staging copy first.
