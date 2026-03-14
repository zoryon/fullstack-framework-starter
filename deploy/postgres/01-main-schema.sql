-- ==============================================================================
-- Nutrico SaaS — Main Schema
-- PostgreSQL 16  |  pgcrypto + uuid-ossp required
--
-- Tenant model: Organisation → Venue. Every operational table carries
-- both org_id and venue_id. RLS policies enforce isolation at DB layer
-- by checking current_setting('app.org_id') set per-transaction by the
-- Go API before any query runs.
--
-- Design rules enforced here:
--   - purchase InventoryMovements are append-only (no DELETE, no UPDATE)
--   - webhook_deliveries are append-only
--   - cost_snapshots are append-only
--   - refresh_tokens: application role cannot DELETE (soft-revoke only)
-- ==============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ==============================================================================
-- ENUM TYPES
-- ==============================================================================

CREATE TYPE "public"."org_plan"                  AS ENUM ('free', 'pro', 'business');
CREATE TYPE "public"."org_role"                  AS ENUM ('owner', 'admin', 'viewer');
CREATE TYPE "public"."auth_provider"             AS ENUM ('email', 'google', 'magic_link');

CREATE TYPE "public"."unit_cost_source"          AS ENUM ('invoice', 'manual');
CREATE TYPE "public"."inventory_movement_type"   AS ENUM ('purchase', 'usage', 'waste', 'adjustment', 'transfer');

CREATE TYPE "public"."po_status"                 AS ENUM ('draft', 'sent', 'invoice_received', 'matched', 'closed', 'cancelled');
CREATE TYPE "public"."invoice_format"            AS ENUM ('FatturaPA', 'UBL', 'CII');
CREATE TYPE "public"."invoice_status"            AS ENUM ('pending', 'parsed', 'matched', 'imported', 'error');

CREATE TYPE "public"."import_job_type"           AS ENUM ('ingredients', 'recipes', 'inventory_counts', 'portions_sold');
CREATE TYPE "public"."import_job_status"         AS ENUM ('queued', 'processing', 'completed', 'failed');

CREATE TYPE "public"."webhook_delivery_status"   AS ENUM ('pending', 'success', 'failed', 'abandoned');

-- ==============================================================================
-- USERS  (global — no org_id, no RLS)
-- ==============================================================================

CREATE TABLE "users" (
    "id"                            uuid        PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "email"                         text        NOT NULL,
    "email_verified"                boolean     DEFAULT false NOT NULL,
    "display_name"                  text,
    "avatar_url"                    text,

    -- Nullable: accounts created via magic link or OAuth may never set a password.
    "password_hash"                 text,

    -- TOTP / MFA (reserved for future release; schema in place now)
    "totp_secret"                   text,
    "totp_enabled"                  boolean     DEFAULT false NOT NULL,
    "totp_backup_codes"             jsonb,      -- encrypted array of one-time codes

    -- Account state
    "is_active"                     boolean     DEFAULT true NOT NULL,
    "is_suspended"                  boolean     DEFAULT false NOT NULL,
    "suspended_reason"              text,

    -- Brute-force protection
    "failed_login_attempts"         integer     DEFAULT 0 NOT NULL,
    "locked_until"                  timestamptz,

    -- Email verification: SHA-256 hash stored here; raw token sent by email only.
    -- Set to NULL once the email is verified.
    "email_verification_token"      text,
    "email_verification_expires"    timestamptz,

    -- Password reset: SHA-256 hash stored here; raw token sent by email only.
    -- Single-use — cleared after successful reset.
    "password_reset_token"          text,
    "password_reset_expires"        timestamptz,

    -- GDPR soft-delete
    "deletion_requested_at"         timestamptz,
    "deleted_at"                    timestamptz,

    "created_at"                    timestamptz DEFAULT now() NOT NULL,
    "updated_at"                    timestamptz DEFAULT now() NOT NULL
);

CREATE UNIQUE INDEX "users_email_idx"              ON "users" ("email");
CREATE INDEX        "users_active_idx"             ON "users" ("is_active");
CREATE INDEX        "users_deletion_requested_idx" ON "users" ("deletion_requested_at");

-- ==============================================================================
-- OAUTH ACCOUNTS  (global — no RLS)
-- ==============================================================================

CREATE TABLE "oauth_accounts" (
    "id"                    uuid        PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "user_id"               uuid        NOT NULL REFERENCES "users" ("id") ON DELETE CASCADE,
    "provider"              auth_provider NOT NULL,
    "provider_account_id"   text        NOT NULL,
    "access_token"          text,       -- encrypted at rest via application layer
    "refresh_token"         text,       -- encrypted at rest via application layer
    "expires_at"            timestamptz,
    "scope"                 text,
    "token_type"            text,
    "created_at"            timestamptz DEFAULT now() NOT NULL,
    "updated_at"            timestamptz DEFAULT now() NOT NULL
);

CREATE UNIQUE INDEX "oauth_provider_account_idx" ON "oauth_accounts" ("provider", "provider_account_id");
CREATE INDEX        "oauth_user_idx"             ON "oauth_accounts" ("user_id");

-- ==============================================================================
-- REFRESH TOKENS  (global — no RLS)
--
-- One row per issued refresh token. Tokens are rotated on every use.
-- family_id groups the rotation chain for a single login event so that
-- reuse of a revoked token (token theft indicator) can invalidate the
-- entire family in one query.
-- Raw token is NEVER stored — only SHA-256(raw) is persisted.
-- ==============================================================================

CREATE TABLE "refresh_tokens" (
    "id"                uuid        PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "user_id"           uuid        NOT NULL REFERENCES "users" ("id") ON DELETE CASCADE,
    -- SHA-256(raw_refresh_token). Raw token lives only in the httpOnly cookie.
    "token_hash"        text        NOT NULL,
    -- Groups the entire rotation chain for one login session.
    -- If any token in the family is reused after rotation, the whole family is revoked.
    "family_id"         uuid        NOT NULL,
    -- Points to the token this row replaced (for audit trail of the rotation chain).
    "previous_token_id" uuid,
    -- Links to the Redis session created alongside this token.
    "session_id"        uuid        NOT NULL,
    -- Soft-revoke only. Application role cannot DELETE this table.
    "revoked_at"        timestamptz,
    "expires_at"        timestamptz NOT NULL, -- 30-day hard ceiling, no sliding window
    -- Set when this token is consumed (exchanged for a new pair). Helps cleanup queries.
    "used_at"           timestamptz,
    "ip_address"        inet,
    "user_agent"        text,
    "created_at"        timestamptz DEFAULT now() NOT NULL
);

CREATE UNIQUE INDEX "refresh_token_hash_idx"   ON "refresh_tokens" ("token_hash");
CREATE INDEX        "refresh_token_family_idx" ON "refresh_tokens" ("family_id");
CREATE INDEX        "refresh_token_user_idx"   ON "refresh_tokens" ("user_id");
CREATE INDEX        "refresh_token_session_idx" ON "refresh_tokens" ("session_id");

-- ==============================================================================
-- ORGANISATIONS  (tenant root — no org_id on this table itself)
-- ==============================================================================

CREATE TABLE "organisations" (
    "id"                    uuid        PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "name"                  text        NOT NULL,
    "slug"                  text        NOT NULL,
    "plan"                  org_plan    DEFAULT 'free' NOT NULL,
    "plan_expires_at"       timestamptz,
    "stripe_customer_id"    text,
    "stripe_subscription_id" text,
    -- Grace flag: set when payment_failed, cleared on invoice.paid
    "payment_grace_until"   timestamptz,
    "is_suspended"          boolean     DEFAULT false NOT NULL,
    "owner_id"              uuid        NOT NULL REFERENCES "users" ("id") ON DELETE NO ACTION,
    "created_at"            timestamptz DEFAULT now() NOT NULL,
    "updated_at"            timestamptz DEFAULT now() NOT NULL,
    "deleted_at"            timestamptz
);

CREATE UNIQUE INDEX "organisations_slug_idx"  ON "organisations" ("slug");
CREATE INDEX        "organisations_owner_idx" ON "organisations" ("owner_id");

-- ==============================================================================
-- ORG MEMBERSHIPS  (no RLS — accessed by user_id lookup before org context is set)
-- ==============================================================================

CREATE TABLE "org_memberships" (
    "id"            uuid        PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "org_id"        uuid        NOT NULL REFERENCES "organisations" ("id") ON DELETE CASCADE,
    "user_id"       uuid        NOT NULL REFERENCES "users" ("id") ON DELETE CASCADE,
    "role"          org_role    NOT NULL,
    "is_active"     boolean     DEFAULT true NOT NULL,
    "invited_by"    uuid        REFERENCES "users" ("id") ON DELETE SET NULL,
    "joined_at"     timestamptz,
    "created_at"    timestamptz DEFAULT now() NOT NULL,
    "updated_at"    timestamptz DEFAULT now() NOT NULL
);

CREATE UNIQUE INDEX "org_memberships_unique_idx"   ON "org_memberships" ("org_id", "user_id");
CREATE INDEX        "org_memberships_org_idx"      ON "org_memberships" ("org_id");
CREATE INDEX        "org_memberships_user_idx"     ON "org_memberships" ("user_id");

-- ==============================================================================
-- ORG INVITES  (no RLS — looked up by token before workspace context is set)
-- ==============================================================================

CREATE TYPE "public"."invite_status" AS ENUM ('pending', 'accepted', 'expired', 'revoked');

CREATE TABLE "org_invites" (
    "id"            uuid            PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "org_id"        uuid            NOT NULL REFERENCES "organisations" ("id") ON DELETE CASCADE,
    "email"         text            NOT NULL,
    "role"          org_role        NOT NULL,
    -- SHA-256(raw_token). Raw token is in the invite email link only.
    "token_hash"    text            NOT NULL,
    "status"        invite_status   DEFAULT 'pending' NOT NULL,
    "expires_at"    timestamptz     NOT NULL,
    "invited_by"    uuid            NOT NULL REFERENCES "users" ("id") ON DELETE NO ACTION,
    "accepted_at"   timestamptz,
    "revoked_at"    timestamptz,
    "revoked_by"    uuid            REFERENCES "users" ("id") ON DELETE NO ACTION,
    "created_at"    timestamptz     DEFAULT now() NOT NULL
);

CREATE UNIQUE INDEX "org_invites_token_hash_idx" ON "org_invites" ("token_hash");
CREATE INDEX        "org_invites_org_idx"        ON "org_invites" ("org_id");
CREATE INDEX        "org_invites_email_idx"      ON "org_invites" ("email");
CREATE INDEX        "org_invites_status_idx"     ON "org_invites" ("status");

-- ==============================================================================
-- VENUES  (tenant-scoped)
-- ==============================================================================

CREATE TABLE "venues" (
    "id"                    uuid        PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "org_id"                uuid        NOT NULL REFERENCES "organisations" ("id") ON DELETE CASCADE,
    "name"                  text        NOT NULL,
    "slug"                  text        NOT NULL,
    "timezone"              text        DEFAULT 'UTC' NOT NULL,
    "currency"              text        DEFAULT 'EUR' NOT NULL,
    -- Default food cost target percentage (e.g. 0.30 = 30%)
    "target_food_cost_pct"  numeric(5,4) DEFAULT 0.3000 NOT NULL,
    "address"               text,
    "is_active"             boolean     DEFAULT true NOT NULL,
    "created_at"            timestamptz DEFAULT now() NOT NULL,
    "updated_at"            timestamptz DEFAULT now() NOT NULL,
    "deleted_at"            timestamptz
);

CREATE UNIQUE INDEX "venues_slug_org_idx" ON "venues" ("org_id", "slug");
CREATE INDEX        "venues_org_idx"      ON "venues" ("org_id");

-- ==============================================================================
-- SUPPLIERS  (tenant-scoped)
-- ==============================================================================

CREATE TABLE "suppliers" (
    "id"                uuid        PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "org_id"            uuid        NOT NULL REFERENCES "organisations" ("id") ON DELETE CASCADE,
    "venue_id"          uuid        NOT NULL REFERENCES "venues" ("id") ON DELETE CASCADE,
    "name"              text        NOT NULL,
    "email"             text,
    "phone"             text,
    "payment_terms"     text,
    "lead_time_days"    integer,
    -- Italian Sistema di Interscambio sender ID — used for FatturaPA auto-matching
    "sdi_code"          text,
    -- VAT / tax number for UBL/CII supplier matching
    "vat_number"        text,
    "is_active"         boolean     DEFAULT true NOT NULL,
    "created_at"        timestamptz DEFAULT now() NOT NULL,
    "updated_at"        timestamptz DEFAULT now() NOT NULL
);

CREATE INDEX "suppliers_org_idx"   ON "suppliers" ("org_id");
CREATE INDEX "suppliers_venue_idx" ON "suppliers" ("venue_id");
CREATE INDEX "suppliers_sdi_idx"   ON "suppliers" ("sdi_code") WHERE "sdi_code" IS NOT NULL;

-- ==============================================================================
-- INGREDIENTS  (tenant-scoped)
--
-- unit_cost is updated EXCLUSIVELY by the electronic invoice pipeline.
-- Manual overrides set unit_cost_source = 'manual' but create no movement.
-- ==============================================================================

CREATE TABLE "ingredients" (
    "id"                uuid            PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "org_id"            uuid            NOT NULL REFERENCES "organisations" ("id") ON DELETE CASCADE,
    "venue_id"          uuid            NOT NULL REFERENCES "venues" ("id") ON DELETE CASCADE,
    "name"              text            NOT NULL,
    "unit"              text            NOT NULL,   -- canonical unit (kg, l, pz, etc.)
    -- Latest known cost per canonical unit. Updated via EWMA on invoice confirmation.
    "unit_cost"         numeric(12,4)   DEFAULT 0 NOT NULL,
    "unit_cost_source"  unit_cost_source DEFAULT 'manual' NOT NULL,
    "reorder_threshold" numeric(12,4),
    "reorder_qty"       numeric(12,4),
    "is_active"         boolean         DEFAULT true NOT NULL,
    "created_at"        timestamptz     DEFAULT now() NOT NULL,
    "updated_at"        timestamptz     DEFAULT now() NOT NULL
);

CREATE INDEX        "ingredients_org_idx"   ON "ingredients" ("org_id");
CREATE INDEX        "ingredients_venue_idx" ON "ingredients" ("venue_id");
CREATE UNIQUE INDEX "ingredients_name_venue_idx" ON "ingredients" ("venue_id", "name");

-- ==============================================================================
-- COST SNAPSHOTS  (append-only — no DELETE, no UPDATE via app role)
--
-- Written every time an ingredient's unit_cost changes (invoice confirmation
-- or manual override). Drives all trend charts and audit trails.
-- ==============================================================================

CREATE TABLE "cost_snapshots" (
    "id"                    uuid            PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "ingredient_id"         uuid            NOT NULL REFERENCES "ingredients" ("id") ON DELETE CASCADE,
    "org_id"                uuid            NOT NULL REFERENCES "organisations" ("id") ON DELETE CASCADE,
    "venue_id"              uuid            NOT NULL REFERENCES "venues" ("id") ON DELETE CASCADE,
    "unit_cost"             numeric(12,4)   NOT NULL,
    "unit_cost_source"      unit_cost_source NOT NULL,
    -- FK to the invoice line that triggered this snapshot (NULL for manual overrides)
    "source_invoice_line_id" uuid,          -- FK added after electronic_invoice_lines table exists
    "effective_from"        timestamptz     NOT NULL DEFAULT now(),
    "created_at"            timestamptz     DEFAULT now() NOT NULL
);

CREATE INDEX "cost_snapshots_ingredient_idx" ON "cost_snapshots" ("ingredient_id");
CREATE INDEX "cost_snapshots_org_idx"        ON "cost_snapshots" ("org_id");
CREATE INDEX "cost_snapshots_venue_idx"      ON "cost_snapshots" ("venue_id");
CREATE INDEX "cost_snapshots_effective_idx"  ON "cost_snapshots" ("ingredient_id", "effective_from");

-- ==============================================================================
-- RECIPES  (tenant-scoped)
-- ==============================================================================

CREATE TABLE "recipes" (
    "id"            uuid        PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "org_id"        uuid        NOT NULL REFERENCES "organisations" ("id") ON DELETE CASCADE,
    "venue_id"      uuid        NOT NULL REFERENCES "venues" ("id") ON DELETE CASCADE,
    "name"          text        NOT NULL,
    "yield_qty"     numeric(12,4) NOT NULL,
    "yield_unit"    text        NOT NULL,
    -- Cost fields are COMPUTED ON READ — never persisted.
    "is_archived"   boolean     DEFAULT false NOT NULL,
    "created_by"    uuid        REFERENCES "users" ("id") ON DELETE SET NULL,
    "created_at"    timestamptz DEFAULT now() NOT NULL,
    "updated_at"    timestamptz DEFAULT now() NOT NULL
);

CREATE INDEX "recipes_org_idx"   ON "recipes" ("org_id");
CREATE INDEX "recipes_venue_idx" ON "recipes" ("venue_id");

-- ==============================================================================
-- RECIPE INGREDIENTS  (join table — supports sub-recipe nesting)
--
-- Either ingredient_id OR sub_recipe_id must be set (enforced by CHECK).
-- Recursive cost rollup capped at 3 levels by application layer.
-- ==============================================================================

CREATE TABLE "recipe_ingredients" (
    "id"                uuid            PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "recipe_id"         uuid            NOT NULL REFERENCES "recipes" ("id") ON DELETE CASCADE,
    -- Exactly one of these two must be set:
    "ingredient_id"     uuid            REFERENCES "ingredients" ("id") ON DELETE RESTRICT,
    "sub_recipe_id"     uuid            REFERENCES "recipes" ("id") ON DELETE RESTRICT,
    "quantity"          numeric(12,4)   NOT NULL,
    "unit"              text            NOT NULL,
    "sort_order"        integer         DEFAULT 0 NOT NULL,
    "created_at"        timestamptz     DEFAULT now() NOT NULL,
    CONSTRAINT "recipe_ingredient_or_subrecipe"
        CHECK (
            (ingredient_id IS NOT NULL AND sub_recipe_id IS NULL)
            OR
            (ingredient_id IS NULL AND sub_recipe_id IS NOT NULL)
        )
);

CREATE INDEX "recipe_ingredients_recipe_idx"     ON "recipe_ingredients" ("recipe_id");
CREATE INDEX "recipe_ingredients_ingredient_idx" ON "recipe_ingredients" ("ingredient_id") WHERE "ingredient_id" IS NOT NULL;
CREATE INDEX "recipe_ingredients_subrecipe_idx"  ON "recipe_ingredients" ("sub_recipe_id") WHERE "sub_recipe_id" IS NOT NULL;

-- ==============================================================================
-- MENU ITEMS  (tenant-scoped)
-- ==============================================================================

CREATE TABLE "menu_items" (
    "id"                    uuid            PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "org_id"                uuid            NOT NULL REFERENCES "organisations" ("id") ON DELETE CASCADE,
    "venue_id"              uuid            NOT NULL REFERENCES "venues" ("id") ON DELETE CASCADE,
    "recipe_id"             uuid            NOT NULL REFERENCES "recipes" ("id") ON DELETE RESTRICT,
    "name"                  text            NOT NULL,
    "category"              text,
    "selling_price"         numeric(12,4)   NOT NULL,
    -- Populated by manual entry or CSV import (portions_sold type)
    "popularity_score"      numeric(12,4),
    "is_active"             boolean         DEFAULT true NOT NULL,
    "created_at"            timestamptz     DEFAULT now() NOT NULL,
    "updated_at"            timestamptz     DEFAULT now() NOT NULL
);

CREATE INDEX "menu_items_org_idx"    ON "menu_items" ("org_id");
CREATE INDEX "menu_items_venue_idx"  ON "menu_items" ("venue_id");
CREATE INDEX "menu_items_recipe_idx" ON "menu_items" ("recipe_id");

-- ==============================================================================
-- INVENTORY ENTRIES  (tenant-scoped)
--
-- Tracks which ingredients are monitored at a venue.
-- Current stock is always derived: SELECT SUM(quantity_delta) FROM inventory_movements
-- WHERE inventory_entry_id = this.id — never a mutable column here.
-- ==============================================================================

CREATE TABLE "inventory_entries" (
    "id"            uuid        PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "org_id"        uuid        NOT NULL REFERENCES "organisations" ("id") ON DELETE CASCADE,
    "venue_id"      uuid        NOT NULL REFERENCES "venues" ("id") ON DELETE CASCADE,
    "ingredient_id" uuid        NOT NULL REFERENCES "ingredients" ("id") ON DELETE RESTRICT,
    "unit"          text        NOT NULL,
    "created_at"    timestamptz DEFAULT now() NOT NULL
);

CREATE UNIQUE INDEX "inventory_entries_unique_idx" ON "inventory_entries" ("venue_id", "ingredient_id");
CREATE INDEX        "inventory_entries_org_idx"    ON "inventory_entries" ("org_id");

-- ==============================================================================
-- INVENTORY MOVEMENTS  (append-only — no DELETE, no UPDATE via app role)
--
-- Source of truth for all stock levels. Every change is a new row.
-- type = 'purchase' is ONLY written by the invoice confirmation pipeline.
-- source_invoice_line_id is mandatory when type = 'purchase'.
-- ==============================================================================

CREATE TABLE "inventory_movements" (
    "id"                        uuid                    PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "org_id"                    uuid                    NOT NULL REFERENCES "organisations" ("id") ON DELETE CASCADE,
    "venue_id"                  uuid                    NOT NULL REFERENCES "venues" ("id") ON DELETE CASCADE,
    "inventory_entry_id"        uuid                    NOT NULL REFERENCES "inventory_entries" ("id") ON DELETE RESTRICT,
    "type"                      inventory_movement_type NOT NULL,
    "quantity_delta"            numeric(12,4)           NOT NULL,   -- positive = stock in, negative = stock out
    "cost_at_time"              numeric(12,4),          -- unit cost at the moment of the movement
    -- Mandatory for type = 'purchase', NULL for all other types.
    -- FK added after electronic_invoice_lines table exists (see deferred FK below).
    "source_invoice_line_id"    uuid,
    "notes"                     text,
    -- Transfer destination (used when type = 'transfer')
    "destination_venue_id"      uuid    REFERENCES "venues" ("id") ON DELETE SET NULL,
    "created_by"                uuid    REFERENCES "users" ("id") ON DELETE SET NULL,
    "created_at"                timestamptz DEFAULT now() NOT NULL,

    CONSTRAINT "purchase_requires_invoice_line"
        CHECK (
            type <> 'purchase' OR source_invoice_line_id IS NOT NULL
        )
);

CREATE INDEX "inventory_movements_org_idx"     ON "inventory_movements" ("org_id");
CREATE INDEX "inventory_movements_venue_idx"   ON "inventory_movements" ("venue_id");
CREATE INDEX "inventory_movements_entry_idx"   ON "inventory_movements" ("inventory_entry_id");
CREATE INDEX "inventory_movements_type_idx"    ON "inventory_movements" ("type");
CREATE INDEX "inventory_movements_created_idx" ON "inventory_movements" ("created_at");
CREATE INDEX "inventory_movements_invoice_idx" ON "inventory_movements" ("source_invoice_line_id") WHERE "source_invoice_line_id" IS NOT NULL;

-- ==============================================================================
-- PURCHASE ORDERS  (tenant-scoped)
--
-- Optional planning documents. Closed exclusively via invoice matching.
-- No qty_received column — actual receipt is driven by ElectronicInvoice.
-- ==============================================================================

CREATE TABLE "purchase_orders" (
    "id"            uuid        PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "org_id"        uuid        NOT NULL REFERENCES "organisations" ("id") ON DELETE CASCADE,
    "venue_id"      uuid        NOT NULL REFERENCES "venues" ("id") ON DELETE CASCADE,
    "supplier_id"   uuid        NOT NULL REFERENCES "suppliers" ("id") ON DELETE RESTRICT,
    "po_number"     text        NOT NULL,
    "status"        po_status   DEFAULT 'draft' NOT NULL,
    "expected_at"   timestamptz,
    -- Linked when an electronic invoice is matched to this PO
    "invoice_id"    uuid,       -- FK added after electronic_invoices table exists
    "notes"         text,
    "created_by"    uuid        REFERENCES "users" ("id") ON DELETE SET NULL,
    "created_at"    timestamptz DEFAULT now() NOT NULL,
    "updated_at"    timestamptz DEFAULT now() NOT NULL
);

CREATE UNIQUE INDEX "purchase_orders_po_number_venue_idx" ON "purchase_orders" ("venue_id", "po_number");
CREATE INDEX        "purchase_orders_org_idx"             ON "purchase_orders" ("org_id");
CREATE INDEX        "purchase_orders_supplier_idx"        ON "purchase_orders" ("supplier_id");
CREATE INDEX        "purchase_orders_status_idx"          ON "purchase_orders" ("status");

-- ==============================================================================
-- PURCHASE ORDER LINES  (tenant-scoped)
--
-- Records expected quantities and prices. No received quantities —
-- those come exclusively from the matched ElectronicInvoiceLine.
-- ==============================================================================

CREATE TABLE "purchase_order_lines" (
    "id"                    uuid            PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "po_id"                 uuid            NOT NULL REFERENCES "purchase_orders" ("id") ON DELETE CASCADE,
    "ingredient_id"         uuid            NOT NULL REFERENCES "ingredients" ("id") ON DELETE RESTRICT,
    "qty_ordered"           numeric(12,4)   NOT NULL,
    "unit_price_expected"   numeric(12,4),  -- expected unit price from PO
    "sort_order"            integer         DEFAULT 0 NOT NULL,
    "created_at"            timestamptz     DEFAULT now() NOT NULL
);

CREATE INDEX "purchase_order_lines_po_idx"          ON "purchase_order_lines" ("po_id");
CREATE INDEX "purchase_order_lines_ingredient_idx"  ON "purchase_order_lines" ("ingredient_id");

-- ==============================================================================
-- ELECTRONIC INVOICES  (tenant-scoped)
--
-- Every uploaded invoice XML is stored in full. Status progresses through
-- the parsing and confirmation pipeline. Never deleted.
-- ==============================================================================

CREATE TABLE "electronic_invoices" (
    "id"                uuid            PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "org_id"            uuid            NOT NULL REFERENCES "organisations" ("id") ON DELETE CASCADE,
    "venue_id"          uuid            NOT NULL REFERENCES "venues" ("id") ON DELETE CASCADE,
    "supplier_id"       uuid            REFERENCES "suppliers" ("id") ON DELETE SET NULL,
    -- Full original XML — immutable after upload
    "raw_xml"           text            NOT NULL,
    "format"            invoice_format  NOT NULL,
    "invoice_number"    text            NOT NULL,
    "invoice_date"      date            NOT NULL,
    "total_amount"      numeric(14,4)   NOT NULL,
    "currency"          text            DEFAULT 'EUR' NOT NULL,
    "status"            invoice_status  DEFAULT 'pending' NOT NULL,
    "error_detail"      jsonb,          -- populated on status = 'error'
    -- Linked PO (if auto-matched or manually assigned)
    "matched_po_id"     uuid            REFERENCES "purchase_orders" ("id") ON DELETE SET NULL,
    "import_job_id"     uuid,           -- FK to import_jobs added below
    -- Overall matching confidence after ingredient review (0.0 – 1.0)
    "confidence_score"  numeric(4,3),
    "uploaded_by"       uuid            REFERENCES "users" ("id") ON DELETE SET NULL,
    "confirmed_by"      uuid            REFERENCES "users" ("id") ON DELETE SET NULL,
    "confirmed_at"      timestamptz,
    "created_at"        timestamptz     DEFAULT now() NOT NULL
);

-- Prevent duplicate invoice numbers per supplier
CREATE UNIQUE INDEX "electronic_invoices_number_supplier_idx"
    ON "electronic_invoices" ("supplier_id", "invoice_number")
    WHERE "supplier_id" IS NOT NULL;

CREATE INDEX "electronic_invoices_org_idx"    ON "electronic_invoices" ("org_id");
CREATE INDEX "electronic_invoices_venue_idx"  ON "electronic_invoices" ("venue_id");
CREATE INDEX "electronic_invoices_status_idx" ON "electronic_invoices" ("status");
CREATE INDEX "electronic_invoices_date_idx"   ON "electronic_invoices" ("invoice_date");

-- ==============================================================================
-- ELECTRONIC INVOICE LINES  (tenant-scoped)
-- ==============================================================================

CREATE TABLE "electronic_invoice_lines" (
    "id"                        uuid            PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "invoice_id"                uuid            NOT NULL REFERENCES "electronic_invoices" ("id") ON DELETE CASCADE,
    "line_number"               integer         NOT NULL,
    "description"               text            NOT NULL,   -- raw description from XML
    "quantity"                  numeric(12,4)   NOT NULL,
    "unit"                      text,           -- unit from XML (may differ from ingredient canonical unit)
    "unit_price"                numeric(12,4)   NOT NULL,
    "total_price"               numeric(14,4)   NOT NULL,
    "tax_rate"                  numeric(5,4),   -- e.g. 0.22 for 22% IVA
    -- Set during the user's matching review. NULL = not yet matched or skipped.
    "matched_ingredient_id"     uuid            REFERENCES "ingredients" ("id") ON DELETE SET NULL,
    -- Confidence score from Levenshtein + token-overlap heuristic (0.0 – 1.0)
    "confidence_score"          numeric(4,3),
    -- True if the user explicitly skipped this line (no movement, no cost update)
    "is_skipped"                boolean         DEFAULT false NOT NULL,
    "created_at"                timestamptz     DEFAULT now() NOT NULL
);

CREATE INDEX "electronic_invoice_lines_invoice_idx"    ON "electronic_invoice_lines" ("invoice_id");
CREATE INDEX "electronic_invoice_lines_ingredient_idx" ON "electronic_invoice_lines" ("matched_ingredient_id") WHERE "matched_ingredient_id" IS NOT NULL;

-- ==============================================================================
-- DEFERRED FOREIGN KEYS — circular/forward references
-- (tables must exist before these can be added)
-- ==============================================================================

-- inventory_movements.source_invoice_line_id → electronic_invoice_lines
ALTER TABLE "inventory_movements"
    ADD CONSTRAINT "inventory_movements_invoice_line_fk"
    FOREIGN KEY ("source_invoice_line_id")
    REFERENCES "electronic_invoice_lines" ("id")
    ON DELETE RESTRICT;

-- cost_snapshots.source_invoice_line_id → electronic_invoice_lines
ALTER TABLE "cost_snapshots"
    ADD CONSTRAINT "cost_snapshots_invoice_line_fk"
    FOREIGN KEY ("source_invoice_line_id")
    REFERENCES "electronic_invoice_lines" ("id")
    ON DELETE SET NULL;

-- purchase_orders.invoice_id → electronic_invoices
ALTER TABLE "purchase_orders"
    ADD CONSTRAINT "purchase_orders_invoice_fk"
    FOREIGN KEY ("invoice_id")
    REFERENCES "electronic_invoices" ("id")
    ON DELETE SET NULL;

-- ==============================================================================
-- IMPORT JOBS  (tenant-scoped)
-- ==============================================================================

CREATE TABLE "import_jobs" (
    "id"                uuid                PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "org_id"            uuid                NOT NULL REFERENCES "organisations" ("id") ON DELETE CASCADE,
    "venue_id"          uuid                NOT NULL REFERENCES "venues" ("id") ON DELETE CASCADE,
    "type"              import_job_type     NOT NULL,
    "status"            import_job_status   DEFAULT 'queued' NOT NULL,
    "total_rows"        integer             DEFAULT 0 NOT NULL,
    "processed_rows"    integer             DEFAULT 0 NOT NULL,
    "error_rows"        integer             DEFAULT 0 NOT NULL,
    "error_detail"      jsonb,              -- per-row errors: [{row: N, error: "..."}]
    "result_url"        text,               -- pre-signed S3/download URL for large exports
    "created_by"        uuid                REFERENCES "users" ("id") ON DELETE SET NULL,
    "created_at"        timestamptz         DEFAULT now() NOT NULL,
    "updated_at"        timestamptz         DEFAULT now() NOT NULL
);

-- Back-fill FK: electronic_invoices.import_job_id → import_jobs
ALTER TABLE "electronic_invoices"
    ADD CONSTRAINT "electronic_invoices_import_job_fk"
    FOREIGN KEY ("import_job_id")
    REFERENCES "import_jobs" ("id")
    ON DELETE SET NULL;

CREATE INDEX "import_jobs_org_idx"    ON "import_jobs" ("org_id");
CREATE INDEX "import_jobs_status_idx" ON "import_jobs" ("status");

-- ==============================================================================
-- WEBHOOK ENDPOINTS  (tenant-scoped)
-- ==============================================================================

CREATE TABLE "webhook_endpoints" (
    "id"                uuid        PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "org_id"            uuid        NOT NULL REFERENCES "organisations" ("id") ON DELETE CASCADE,
    -- HMAC-SHA256 secret — stored as hash; raw secret returned only at creation time
    "secret_hash"       text        NOT NULL,
    "url"               text        NOT NULL,
    -- JSON array of subscribed event names e.g. ["recipe.cost_changed", "inventory.low_stock"]
    "event_filter"      jsonb       NOT NULL DEFAULT '[]'::jsonb,
    "is_active"         boolean     DEFAULT true NOT NULL,
    "failure_count"     integer     DEFAULT 0 NOT NULL,
    -- Set after 3 consecutive failures; org owner notified
    "disabled_at"       timestamptz,
    "created_by"        uuid        REFERENCES "users" ("id") ON DELETE SET NULL,
    "created_at"        timestamptz DEFAULT now() NOT NULL,
    "updated_at"        timestamptz DEFAULT now() NOT NULL
);

CREATE INDEX "webhook_endpoints_org_idx" ON "webhook_endpoints" ("org_id");

-- ==============================================================================
-- WEBHOOK DELIVERIES  (append-only — no DELETE, no UPDATE via app role)
-- ==============================================================================

CREATE TABLE "webhook_deliveries" (
    "id"            uuid                    PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    "endpoint_id"   uuid                    NOT NULL REFERENCES "webhook_endpoints" ("id") ON DELETE CASCADE,
    "org_id"        uuid                    NOT NULL REFERENCES "organisations" ("id") ON DELETE CASCADE,
    "event_type"    text                    NOT NULL,
    -- SHA-256 of the JSON payload (for deduplication / audit)
    "payload_hash"  text                    NOT NULL,
    "status"        webhook_delivery_status DEFAULT 'pending' NOT NULL,
    "http_status"   integer,
    "duration_ms"   integer,
    "attempt_number" integer                DEFAULT 1 NOT NULL,
    "error_detail"  text,
    "attempted_at"  timestamptz             DEFAULT now() NOT NULL
);

CREATE INDEX "webhook_deliveries_endpoint_idx"    ON "webhook_deliveries" ("endpoint_id");
CREATE INDEX "webhook_deliveries_org_idx"         ON "webhook_deliveries" ("org_id");
CREATE INDEX "webhook_deliveries_attempted_at_idx" ON "webhook_deliveries" ("attempted_at");

-- ==============================================================================
-- ROW LEVEL SECURITY (RLS)
-- Multi-tenant isolation enforced at DB layer.
-- app.org_id is set per-transaction via SET LOCAL by the Go API before
-- any query executes. Even broken application code cannot leak cross-org data.
-- ==============================================================================

ALTER TABLE "venues"                    ENABLE ROW LEVEL SECURITY;
ALTER TABLE "suppliers"                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE "ingredients"               ENABLE ROW LEVEL SECURITY;
ALTER TABLE "cost_snapshots"            ENABLE ROW LEVEL SECURITY;
ALTER TABLE "recipes"                   ENABLE ROW LEVEL SECURITY;
ALTER TABLE "recipe_ingredients"        ENABLE ROW LEVEL SECURITY;
ALTER TABLE "menu_items"                ENABLE ROW LEVEL SECURITY;
ALTER TABLE "inventory_entries"         ENABLE ROW LEVEL SECURITY;
ALTER TABLE "inventory_movements"       ENABLE ROW LEVEL SECURITY;
ALTER TABLE "purchase_orders"           ENABLE ROW LEVEL SECURITY;
ALTER TABLE "purchase_order_lines"      ENABLE ROW LEVEL SECURITY;
ALTER TABLE "electronic_invoices"       ENABLE ROW LEVEL SECURITY;
ALTER TABLE "electronic_invoice_lines"  ENABLE ROW LEVEL SECURITY;
ALTER TABLE "import_jobs"               ENABLE ROW LEVEL SECURITY;
ALTER TABLE "webhook_endpoints"         ENABLE ROW LEVEL SECURITY;
ALTER TABLE "webhook_deliveries"        ENABLE ROW LEVEL SECURITY;
ALTER TABLE "org_memberships"           ENABLE ROW LEVEL SECURITY;
ALTER TABLE "org_invites"               ENABLE ROW LEVEL SECURITY;

-- Direct org_id column — one policy per table
CREATE POLICY "tenant_isolation" ON "venues"
    USING (org_id = current_setting('app.org_id', true)::uuid);

CREATE POLICY "tenant_isolation" ON "suppliers"
    USING (org_id = current_setting('app.org_id', true)::uuid);

CREATE POLICY "tenant_isolation" ON "ingredients"
    USING (org_id = current_setting('app.org_id', true)::uuid);

CREATE POLICY "tenant_isolation" ON "cost_snapshots"
    USING (org_id = current_setting('app.org_id', true)::uuid);

CREATE POLICY "tenant_isolation" ON "recipes"
    USING (org_id = current_setting('app.org_id', true)::uuid);

CREATE POLICY "tenant_isolation" ON "menu_items"
    USING (org_id = current_setting('app.org_id', true)::uuid);

CREATE POLICY "tenant_isolation" ON "inventory_entries"
    USING (org_id = current_setting('app.org_id', true)::uuid);

CREATE POLICY "tenant_isolation" ON "inventory_movements"
    USING (org_id = current_setting('app.org_id', true)::uuid);

CREATE POLICY "tenant_isolation" ON "purchase_orders"
    USING (org_id = current_setting('app.org_id', true)::uuid);

CREATE POLICY "tenant_isolation" ON "electronic_invoices"
    USING (org_id = current_setting('app.org_id', true)::uuid);

CREATE POLICY "tenant_isolation" ON "import_jobs"
    USING (org_id = current_setting('app.org_id', true)::uuid);

CREATE POLICY "tenant_isolation" ON "webhook_endpoints"
    USING (org_id = current_setting('app.org_id', true)::uuid);

CREATE POLICY "tenant_isolation" ON "webhook_deliveries"
    USING (org_id = current_setting('app.org_id', true)::uuid);

CREATE POLICY "tenant_isolation" ON "org_memberships"
    USING (org_id = current_setting('app.org_id', true)::uuid);

CREATE POLICY "tenant_isolation" ON "org_invites"
    USING (org_id = current_setting('app.org_id', true)::uuid);

-- Join-through tables: scope via parent FK using EXISTS
CREATE POLICY "tenant_isolation" ON "recipe_ingredients"
    USING (
        EXISTS (
            SELECT 1 FROM recipes r
            WHERE r.id = recipe_id
              AND r.org_id = current_setting('app.org_id', true)::uuid
        )
    );

CREATE POLICY "tenant_isolation" ON "purchase_order_lines"
    USING (
        EXISTS (
            SELECT 1 FROM purchase_orders po
            WHERE po.id = po_id
              AND po.org_id = current_setting('app.org_id', true)::uuid
        )
    );

CREATE POLICY "tenant_isolation" ON "electronic_invoice_lines"
    USING (
        EXISTS (
            SELECT 1 FROM electronic_invoices ei
            WHERE ei.id = invoice_id
              AND ei.org_id = current_setting('app.org_id', true)::uuid
        )
    );

-- ==============================================================================
-- UPDATED_AT TRIGGER
-- ==============================================================================

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER "users_updated_at"
    BEFORE UPDATE ON "users"
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER "oauth_accounts_updated_at"
    BEFORE UPDATE ON "oauth_accounts"
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER "organisations_updated_at"
    BEFORE UPDATE ON "organisations"
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER "org_memberships_updated_at"
    BEFORE UPDATE ON "org_memberships"
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER "venues_updated_at"
    BEFORE UPDATE ON "venues"
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER "suppliers_updated_at"
    BEFORE UPDATE ON "suppliers"
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER "ingredients_updated_at"
    BEFORE UPDATE ON "ingredients"
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER "recipes_updated_at"
    BEFORE UPDATE ON "recipes"
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER "menu_items_updated_at"
    BEFORE UPDATE ON "menu_items"
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER "purchase_orders_updated_at"
    BEFORE UPDATE ON "purchase_orders"
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER "webhook_endpoints_updated_at"
    BEFORE UPDATE ON "webhook_endpoints"
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER "import_jobs_updated_at"
    BEFORE UPDATE ON "import_jobs"
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ==============================================================================
-- APPEND-ONLY ENFORCEMENT TRIGGERS
--
-- Belt-and-suspenders on top of the role-level REVOKE below.
-- Fires even if someone connects with a higher-privilege role by mistake.
-- ==============================================================================

CREATE OR REPLACE FUNCTION deny_update_or_delete()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Table % is append-only: UPDATE and DELETE are not permitted.', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER "inventory_movements_append_only"
    BEFORE UPDATE OR DELETE ON "inventory_movements"
    FOR EACH ROW EXECUTE FUNCTION deny_update_or_delete();

CREATE TRIGGER "cost_snapshots_append_only"
    BEFORE UPDATE OR DELETE ON "cost_snapshots"
    FOR EACH ROW EXECUTE FUNCTION deny_update_or_delete();

CREATE TRIGGER "webhook_deliveries_append_only"
    BEFORE UPDATE OR DELETE ON "webhook_deliveries"
    FOR EACH ROW EXECUTE FUNCTION deny_update_or_delete();

-- ==============================================================================
-- GDPR: IP PSEUDONYMISATION
-- Zeroes the last octet of any inet column older than 30 days.
-- Called by the Asynq scheduled worker daily — never by the API directly.
-- Applies to: refresh_tokens.ip_address, org_invites (no IP), users (no IP).
-- ==============================================================================

CREATE OR REPLACE FUNCTION pseudonymise_old_ips()
RETURNS void AS $$
BEGIN
    -- Refresh tokens: null-out IP after 30 days
    UPDATE refresh_tokens
    SET ip_address = NULL
    WHERE created_at < now() - INTERVAL '30 days'
      AND ip_address IS NOT NULL;
END;
$$ LANGUAGE plpgsql;

-- ==============================================================================
-- CLEANUP FUNCTIONS
-- Called by Asynq scheduled workers — never by the API directly.
-- ==============================================================================

-- Purge fully-consumed and expired refresh tokens older than 7 days.
-- is_revoked is the application soft-revoke flag; used_at marks consumption.
CREATE OR REPLACE FUNCTION cleanup_refresh_tokens()
RETURNS void AS $$
BEGIN
    DELETE FROM refresh_tokens
    WHERE (
            (revoked_at IS NOT NULL OR expires_at < now())
            AND used_at IS NOT NULL
          )
      AND created_at < now() - INTERVAL '7 days';
END;
$$ LANGUAGE plpgsql;

-- Purge soft-deleted users after the required retention window.
CREATE OR REPLACE FUNCTION cleanup_deleted_users()
RETURNS void AS $$
BEGIN
    DELETE FROM users
    WHERE deleted_at IS NOT NULL
      AND deleted_at < now() - INTERVAL '90 days';
END;
$$ LANGUAGE plpgsql;
