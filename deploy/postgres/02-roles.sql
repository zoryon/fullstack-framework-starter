-- ==============================================================================
-- Nutrico SaaS — DB Role Setup (local dev)
-- Runs automatically after main-schema.sql on first container boot.
--
-- Creates the nutrico_user role — the only role the Go API and Asynq
-- worker use at runtime. The postgres superuser is only used during
-- init (CREATE EXTENSION, schema creation).
--
-- Permission model (mirrors production exactly):
--   - Full SELECT/INSERT/UPDATE/DELETE on all tables
--   - EXCEPT append-only tables: INSERT only, no UPDATE or DELETE
--   - EXCEPT refresh_tokens: no DELETE (soft-revoke only via revoked_at)
--   - EXCEPT organisations: no DELETE (only soft-delete via deleted_at)
--   - EXCEPT users: no DELETE (only soft-delete via deleted_at)
--
-- Append-only tables (no UPDATE, no DELETE):
--   - inventory_movements   — every stock change is a permanent record
--   - cost_snapshots        — every price change is a permanent record
--   - webhook_deliveries    — delivery log is a permanent audit trail
--
-- The main-schema.sql also installs BEFORE UPDATE OR DELETE triggers on
-- these tables as a belt-and-suspenders safety net.
-- ==============================================================================

-- Create the restricted application role
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'nutrico_user') THEN
        -- Keep in sync with POSTGRES_APP_DB_PASSWORD default in .env/.env.example.
        CREATE ROLE nutrico_user WITH LOGIN PASSWORD 'admin';
    ELSE
        -- Ensure existing role password stays aligned with runtime credentials.
        ALTER ROLE nutrico_user WITH LOGIN PASSWORD 'admin';
    END IF;
END $$;

-- ── Standard permissions on all existing tables ───────────────────────────────

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO nutrico_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO nutrico_user;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO nutrico_user;

-- Ensure future tables created by migrations are also accessible
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO nutrico_user;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO nutrico_user;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT EXECUTE ON FUNCTIONS TO nutrico_user;

-- ── Append-only enforcement ───────────────────────────────────────────────────

-- inventory_movements: append-only stock ledger.
-- Every purchase movement is the direct result of a confirmed electronic invoice.
-- Allowing DELETE would silently corrupt stock levels and invoice audit trails.
REVOKE UPDATE, DELETE ON inventory_movements FROM nutrico_user;

-- cost_snapshots: append-only price history.
-- Drives all trend charts and the audit trail linking price changes to invoices.
-- Deletion would break historical food-cost-% reporting.
REVOKE UPDATE, DELETE ON cost_snapshots FROM nutrico_user;

-- webhook_deliveries: append-only delivery log.
-- Each attempt is a permanent record for debugging and SLA auditing.
REVOKE UPDATE, DELETE ON webhook_deliveries FROM nutrico_user;

-- ── Soft-delete-only tables ───────────────────────────────────────────────────

-- refresh_tokens: never hard-deleted by the application.
-- Revocation is soft (revoked_at timestamp). Hard deletes are performed only
-- by the cleanup_refresh_tokens() scheduled function (called via Asynq worker,
-- which connects as the same role — the function itself uses SECURITY DEFINER
-- if deletion rights are needed, or runs as superuser in a dedicated job).
REVOKE DELETE ON refresh_tokens FROM nutrico_user;

-- organisations: soft-deleted via deleted_at only.
-- Hard deletes are performed only by a manual ops procedure after data export.
REVOKE DELETE ON organisations FROM nutrico_user;

-- users: soft-deleted via deleted_at (GDPR workflow).
-- Hard deletes performed only by cleanup_deleted_users() after 90-day retention window.
REVOKE DELETE ON users FROM nutrico_user;

-- ── Read-only safety on global auth tables (extra hardening) ─────────────────

-- oauth_accounts: the application may INSERT new linked accounts and UPDATE
-- tokens, but provider account links are never hard-deleted by the app — only
-- when the parent user is fully purged (handled by CASCADE in main-schema.sql).
-- No explicit REVOKE needed beyond the CASCADE guarantee.

-- ── Grant explicit EXECUTE on maintenance functions ──────────────────────────
-- These are called by the Asynq scheduled worker at runtime.
GRANT EXECUTE ON FUNCTION pseudonymise_old_ips()    TO nutrico_user;
GRANT EXECUTE ON FUNCTION cleanup_refresh_tokens()  TO nutrico_user;
GRANT EXECUTE ON FUNCTION cleanup_deleted_users()   TO nutrico_user;
