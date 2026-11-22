# QuantLite

QuantLite is a role-based microplastic monitoring workspace. The static frontend is in `microplastic-monitor/`; the API is in `backend/`.

## Current implementation

- Separate customer and founder/co-founder login portals. Public registration always creates a customer; owner accounts are provisioned server-side and require MFA.
- Customer email verification and password reset token flows. In development, tokens are returned by the API when SMTP is not configured. Production must configure SMTP delivery.
- Server-side authorization for all customer and admin routes; customers' test, analytics, map, and report queries are scoped to their authenticated user ID.
- Secure HTTP-only session cookies, same-site cookie policy, a session-bound CSRF token, and configurable session expiration.
- Customer profile onboarding/editing, pending sample record creation, private test history, profile management, and personal analytics.
- Admin command center, customer directory and status management, test filters and CSV export, regional summaries, analytics, report inventory, profile, and system status.
- Records without model output remain pending. There are no fabricated analysis results. Image inference and report file generation are not configured.

## Local setup

Python 3.11+ is recommended. From the repository root, install the API dependencies:

```powershell
python -m pip install -r requirements.txt
```

Copy `.env.example` to `.env`. For local use, SQLite is configured by default. Set `BOOTSTRAP_OWNER_EMAIL` to the verified startup founder who will own the first account. Generate `OWNER_MFA_ENCRYPTION_KEY` with the command below and store it in the backend environment or secret manager; losing it requires owner-controlled MFA recovery. The database schema and migrations are applied on API startup and tracked in `schema_migrations`.

Start the API in one PowerShell window:

```powershell
python -m uvicorn backend.main:app --reload --port 8000
```

Start the frontend in another window:

```powershell
cd microplastic-monitor
python -m http.server 8765
```

Open `http://localhost:8765`. Run both servers: the API on port 8000 and the frontend on port 8765. If you use VS Code Live Server on port 5500, its localhost origins are included in the default CORS list. If you change the frontend port, add its `http://localhost:<port>` and `http://127.0.0.1:<port>` origins to `CORS_ORIGINS`. The frontend API origin is the `API_BASE_URL` setting near the top of `microplastic-monitor/app.js`; edit it if the API runs at a different address. Frontend URL, session duration, and SMTP settings are configured in the backend environment.

## Founder ownership, provisioning, MFA, and recovery

Public registration creates customer accounts only. No request field, profile edit, or frontend route grants owner privileges. The internal `ADMIN` role represents verified founders and co-founders only and is enforced by backend authorization on every platform-wide endpoint. Customers can read and change only their own permitted data.

Generate and store the MFA encryption key before provisioning. Never commit it to source control:

```powershell
python -m backend.provision_admin --generate-encryption-key
```

Set `BOOTSTRAP_OWNER_EMAIL` to the first founder's address, then provision that account. The first provision is allowed only when there are no owner accounts. After that, adding a founder or replacing an owner's credentials requires a different active, verified founder to approve with their password and current TOTP code. A customer account cannot be elevated. The command records approvals in the audit chain.

```powershell
python -m backend.provision_admin founder@example.org
```

The command prompts for the founder's full name and a 12+ character password, then displays the TOTP setup secret/URI and ten one-time recovery codes once. Deliver these through the approved secure channel and store recovery codes offline. The database stores the MFA secret encrypted with `OWNER_MFA_ENCRYPTION_KEY`; every founder login requires TOTP or a one-use recovery code. Recovery codes cannot approve ownership changes. For lost MFA or suspected compromise, another verified founder must use this same dual-control command after re-authenticating; this rotates credentials, MFA and sessions. If no other founder can approve, use the organization's documented identity-verified incident recovery process to restore founder control before changing the bootstrap state. Do not use customer support or customer self-service reset for owner accounts.

Sensitive actions are recorded in append-only database audit logs linked by SHA-256 hashes. SQLite and PostgreSQL reject updates/deletes at the database layer, and founders can check the chain at `/api/admin/audit/verify`. Keep database backups and encryption keys under separate access controls; hash chaining detects modification but is not a substitute for independently retained backups or restricted database access.

## PostgreSQL

The API supports SQLite for local development and PostgreSQL through psycopg 3. To use PostgreSQL, install `requirements.txt`, configure a private `DATABASE_URL=postgresql://...` in the backend environment, and set `APP_ENV=production`, `CORS_ORIGINS`, `FRONTEND_BASE_URL`, secure SMTP settings, and a strong deployment secret policy. No database URL or credential belongs in frontend code. The API schema uses explicit IDs and constraints and applies the initial migration automatically. Back up and test schema migration upgrades before production rollout.

## Test the API

```powershell
python -m unittest backend.test_api -v
node --check microplastic-monitor/app.js
```

The authorization checks cover customer-only account creation, email verification, portal-role checks, CSRF enforcement, mandatory founder MFA, one-use recovery codes, audit-chain integrity, and customer test-record isolation.

## Remaining integrations and deployment work

- Set up and verify a real PostgreSQL instance, backups, TLS, secrets management, and production deployment.
- Configure a production email provider and verify registration/reset messages and link routing.
- Add API rate limiting and operational monitoring at the API gateway before exposing authentication publicly.
- Confirm the replacement model's image contract, labels, units, confidence semantics, and result schema. Then implement and test the inference endpoint; current analysis actions remain disabled.
- Configure a report renderer and private file storage before enabling generated report downloads.
- Select a production map tile provider if required. Current map rendering uses real OpenStreetMap tiles, attribution, and only stored coordinates; provider availability is required.
- Add automated frontend browser/accessibility coverage and deployment-level authorization tests.

PostgreSQL connectivity and production email delivery were not exercised in the local test run. The static frontend remains exactly three source files: `index.html`, `styles.css`, and `app.js`.
