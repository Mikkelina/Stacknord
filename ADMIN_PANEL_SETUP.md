# StackNord Admin Foundation

This branch contains a preliminary admin foundation for the existing Express + SQLite app. It adds staff login/roles, user management, support tickets and guarded payment review for manual payment methods.

## Status and limitations

This is not a certified or security-audited product. It must be installed and tested on a staging copy before production. `server.js` remains unchanged until the operator explicitly runs the integration script, which creates a timestamped backup and stops if expected source anchors are absent.

Implemented in code:
- Staff-only login with session regeneration, an eight-hour admin session limit, and basic per-IP throttling.
- Built-in admin/moderator/support roles and custom limited roles.
- User listing/creation, ban/unban, staff role assignment, and protection against banning/demoting the last active admin.
- Order listing and manual review for PayPal, crypto, and Vipps. Stripe payment status is only changed by the signed webhook; refunds are not exposed.
- Customer support tickets, customer-owned ticket views, staff replies/statuses, and audit entries.
- Audit log views, configurable audit retention (default 90 days, 30–3650 days allowed), and account-status enforcement for existing signed-in sessions.
- Automated smoke tests for DB migrations and route registration (`npm test`).

Not included: Stripe invoicing/PDF/email, product/plan editing, application MFA, password recovery, email notifications for support replies, and a full security audit. These need explicit implementation/review; don't treat this as complete business software or deploy without staging tests.

## Integrate locally

1. Back up the project and SQLite database. Stop the app before copying SQLite data so WAL contents are handled safely.
2. From the project root, run `node scripts/integrate-admin.js`.
3. Run `node --check server.js`, then `npm install` and `npm test`. Start a staging instance.
4. Create an account on staging and promote it as administrator (the script uses `DATABASE_PATH` if configured, otherwise `data/stacknord.sqlite`):
   ```bash
   ADMIN_EMAIL=you@example.com node scripts/promote-admin.js
   ```
5. Sign in at `/admin/login`. Verify customer access at `/support`, staff responses at `/admin/support`, bans, roles, CSRF, checkout and webhooks before production.

Use HTTPS, a unique strong password, least privilege, backups, and appropriate log/IP retention and privacy notices. MFA is not implemented in the application yet.
