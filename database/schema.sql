
-- SRIRAM & RAMANI WEDDING PLATFORM — PRODUCTION DATABASE SCHEMA v5.0
-- PostgreSQL 15 / Supabase
-- Run this in: Supabase Dashboard → SQL Editor → New Query
-- ═══════════════════════════════════════════════════════════════════
 
-- ── EXTENSIONS ──────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";     -- fast LIKE/ILIKE queries
CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- ═══════════════════════════════════════════════════════════════════
-- TABLES
-- ═══════════════════════════════════════════════════════════════════
 
-- ── RSVPS ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rsvps (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  guest_name      text        NOT NULL,
  email           text        DEFAULT NULL,
  phone           text        DEFAULT NULL,
  guests_count    smallint    NOT NULL DEFAULT 1,
  attending       boolean     NOT NULL,
  meal_preference text        DEFAULT NULL,
  notes           text        DEFAULT NULL,
  ip_hash         text        DEFAULT NULL,     -- hashed for abuse detection
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
 
  CONSTRAINT rsvps_guest_name_len   CHECK (char_length(guest_name) BETWEEN 1 AND 100),
  CONSTRAINT rsvps_email_format     CHECK (email IS NULL OR email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  CONSTRAINT rsvps_phone_len        CHECK (phone IS NULL OR char_length(phone) <= 25),
  CONSTRAINT rsvps_guests_range     CHECK (guests_count BETWEEN 1 AND 20),
  CONSTRAINT rsvps_meal_values      CHECK (meal_preference IS NULL OR meal_preference IN
    ('no-preference','vegetarian','non-vegetarian','vegan','jain')),
  CONSTRAINT rsvps_notes_len        CHECK (notes IS NULL OR char_length(notes) <= 500)
);
 
CREATE INDEX idx_rsvps_created_at    ON rsvps (created_at DESC);
CREATE INDEX idx_rsvps_attending     ON rsvps (attending);
CREATE INDEX idx_rsvps_guest_name    ON rsvps USING gin (guest_name gin_trgm_ops);
CREATE INDEX idx_rsvps_ip_hash       ON rsvps (ip_hash, created_at);
CREATE INDEX idx_rsvps_meal          ON rsvps (meal_preference) WHERE attending = true;
 
-- ── BLESSINGS ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS blessings (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text        NOT NULL,
  relation    text        DEFAULT NULL,
  message     text        NOT NULL,
  is_approved boolean     NOT NULL DEFAULT true,
  ip_hash     text        DEFAULT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
 
  CONSTRAINT blessings_name_len     CHECK (char_length(name) BETWEEN 1 AND 80),
  CONSTRAINT blessings_relation_len CHECK (relation IS NULL OR char_length(relation) <= 60),
  CONSTRAINT blessings_message_len  CHECK (char_length(message) BETWEEN 1 AND 500)
);
 
CREATE INDEX idx_blessings_created_at ON blessings (created_at DESC);
CREATE INDEX idx_blessings_approved   ON blessings (is_approved, created_at DESC);
 
-- ── MEMORIES (Memory Wall) ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS memories (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  author_name   text        DEFAULT NULL,
  caption       text        DEFAULT NULL,
  storage_path  text        NOT NULL UNIQUE,
  public_url    text        DEFAULT NULL,
  file_size     integer     DEFAULT NULL,
  mime_type     text        NOT NULL,
  is_approved   boolean     NOT NULL DEFAULT true,
  ip_hash       text        DEFAULT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
 
  CONSTRAINT memories_author_len    CHECK (author_name IS NULL OR char_length(author_name) <= 60),
  CONSTRAINT memories_caption_len   CHECK (caption IS NULL OR char_length(caption) <= 200),
  CONSTRAINT memories_size_limit    CHECK (file_size IS NULL OR file_size <= 10485760),
  CONSTRAINT memories_mime_values   CHECK (mime_type IN ('image/jpeg','image/png','image/webp'))
);
 
CREATE INDEX idx_memories_created_at ON memories (created_at DESC);
CREATE INDEX idx_memories_approved   ON memories (is_approved, created_at DESC);
 
-- ── CONTACT INFORMATION ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS contact_information (
  id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  role           text        NOT NULL,
  display_name   text        NOT NULL,
  phone          text        DEFAULT NULL,
  whatsapp       text        DEFAULT NULL,
  email          text        DEFAULT NULL,
  description    text        DEFAULT NULL,
  display_order  smallint    NOT NULL DEFAULT 0,
  is_emergency   boolean     NOT NULL DEFAULT false,
  is_active      boolean     NOT NULL DEFAULT true,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
 
  CONSTRAINT contact_role_len  CHECK (char_length(role) <= 60),
  CONSTRAINT contact_name_len  CHECK (char_length(display_name) BETWEEN 1 AND 100),
  CONSTRAINT contact_email_fmt CHECK (email IS NULL OR email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$')
);
 
CREATE INDEX idx_contact_display_order ON contact_information (display_order) WHERE is_active = true;
 
-- ── SUPPORT REQUESTS ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS support_requests (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text        NOT NULL,
  phone       text        DEFAULT NULL,
  email       text        DEFAULT NULL,
  category    text        NOT NULL DEFAULT 'general',
  message     text        NOT NULL,
  status      text        NOT NULL DEFAULT 'open',
  ip_hash     text        DEFAULT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
 
  CONSTRAINT support_name_len     CHECK (char_length(name) BETWEEN 1 AND 100),
  CONSTRAINT support_phone_len    CHECK (phone IS NULL OR char_length(phone) <= 25),
  CONSTRAINT support_email_fmt    CHECK (email IS NULL OR email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  CONSTRAINT support_category     CHECK (category IN ('directions','meal','accommodation','general','other')),
  CONSTRAINT support_message_len  CHECK (char_length(message) BETWEEN 5 AND 1000),
  CONSTRAINT support_status       CHECK (status IN ('open','in-progress','resolved'))
);
 
CREATE INDEX idx_support_status     ON support_requests (status, created_at DESC);
CREATE INDEX idx_support_created_at ON support_requests (created_at DESC);
 
-- ── INVITATION ASSETS ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS invitation_assets (
  id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  label          text        NOT NULL DEFAULT 'Wedding Invitation',
  storage_path   text        NOT NULL UNIQUE,
  public_url     text        DEFAULT NULL,
  mime_type      text        NOT NULL,
  file_size      integer     DEFAULT NULL,
  page_number    smallint    DEFAULT 1,
  is_primary     boolean     NOT NULL DEFAULT false,
  display_order  smallint    NOT NULL DEFAULT 0,
  uploaded_by    uuid        REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
 
  CONSTRAINT invitation_mime CHECK (mime_type IN
    ('application/pdf','image/jpeg','image/png','image/webp'))
);
 
CREATE INDEX idx_invitation_primary ON invitation_assets (display_order) WHERE is_primary = true;
 
-- ── ADMIN LOGS (Audit Trail) ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS admin_logs (
  id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_id     uuid        REFERENCES auth.users(id) ON DELETE SET NULL,
  admin_email  text        DEFAULT NULL,
  action       text        NOT NULL,
  target_type  text        DEFAULT NULL,
  target_id    uuid        DEFAULT NULL,
  details      jsonb       DEFAULT NULL,
  ip_hash      text        DEFAULT NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);
 
CREATE INDEX idx_admin_logs_created_at  ON admin_logs (created_at DESC);
CREATE INDEX idx_admin_logs_action      ON admin_logs (action, created_at DESC);
CREATE INDEX idx_admin_logs_target      ON admin_logs (target_type, target_id);
 
-- ── ANALYTICS ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS analytics_events (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type  text        NOT NULL,
  section     text        DEFAULT NULL,
  metadata    jsonb       DEFAULT NULL,
  ip_hash     text        DEFAULT NULL,
  user_agent  text        DEFAULT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
 
CREATE INDEX idx_analytics_event_type ON analytics_events (event_type, created_at DESC);
CREATE INDEX idx_analytics_created_at ON analytics_events (created_at DESC);
 
-- Partition hint: for >100k rows, partition by created_at month
-- ALTER TABLE analytics_events PARTITION BY RANGE (created_at);
 
-- ═══════════════════════════════════════════════════════════════════
-- TRIGGERS
-- ═══════════════════════════════════════════════════════════════════
 
CREATE OR REPLACE FUNCTION trigger_set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;
 
CREATE TRIGGER rsvps_set_updated_at
  BEFORE UPDATE ON rsvps FOR EACH ROW
  EXECUTE FUNCTION trigger_set_updated_at();
 
CREATE TRIGGER contact_set_updated_at
  BEFORE UPDATE ON contact_information FOR EACH ROW
  EXECUTE FUNCTION trigger_set_updated_at();
 
CREATE TRIGGER support_set_updated_at
  BEFORE UPDATE ON support_requests FOR EACH ROW
  EXECUTE FUNCTION trigger_set_updated_at();
 
-- ═══════════════════════════════════════════════════════════════════
-- ROW LEVEL SECURITY
-- All production data access routes through the backend service key.
-- RLS provides defense-in-depth — not the primary auth layer.
-- ═══════════════════════════════════════════════════════════════════
 
-- RSVPs — no public read; insert via backend API only
ALTER TABLE rsvps ENABLE ROW LEVEL SECURITY;
-- Service key (backend) bypasses RLS. No anon policies needed.
-- This prevents any direct table access from the browser.
 
-- Blessings — public read of approved; insert via backend only
ALTER TABLE blessings ENABLE ROW LEVEL SECURITY;
CREATE POLICY "blessings_public_read" ON blessings
  FOR SELECT USING (is_approved = true);
-- INSERT handled server-side with service key
 
-- Memories — public read of approved
ALTER TABLE memories ENABLE ROW LEVEL SECURITY;
CREATE POLICY "memories_public_read" ON memories
  FOR SELECT USING (is_approved = true);
 
-- Contact info — public read of active records
ALTER TABLE contact_information ENABLE ROW LEVEL SECURITY;
CREATE POLICY "contact_public_read" ON contact_information
  FOR SELECT USING (is_active = true);
 
-- Support requests — no public access
ALTER TABLE support_requests ENABLE ROW LEVEL SECURITY;
 
-- Invitation assets — public read
ALTER TABLE invitation_assets ENABLE ROW LEVEL SECURITY;
CREATE POLICY "invitation_public_read" ON invitation_assets
  FOR SELECT USING (true);
 
-- Admin logs — no public access
ALTER TABLE admin_logs ENABLE ROW LEVEL SECURITY;
 
-- Analytics — no public access
ALTER TABLE analytics_events ENABLE ROW LEVEL SECURITY;
 
-- ═══════════════════════════════════════════════════════════════════
-- STORAGE BUCKETS
-- Run these in Supabase Dashboard → Storage, or via SQL:
-- ═══════════════════════════════════════════════════════════════════
 
-- Memory wall photos (public read, API write only)
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'memories', 'memories', true,
  5242880,  -- 5 MB max
  ARRAY['image/jpeg','image/png','image/webp']
) ON CONFLICT (id) DO NOTHING;
 
-- Official invitation files (public read, admin write only)
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'invitations', 'invitations', true,
  52428800,  -- 50 MB max (hi-res PDFs)
  ARRAY['application/pdf','image/jpeg','image/png','image/webp']
) ON CONFLICT (id) DO NOTHING;
 
-- Storage RLS: public read, no anon write
CREATE POLICY "memories_public_read" ON storage.objects
  FOR SELECT USING (bucket_id = 'memories');
 
CREATE POLICY "invitations_public_read" ON storage.objects
  FOR SELECT USING (bucket_id = 'invitations');
 
-- ═══════════════════════════════════════════════════════════════════
-- SEED DATA — Update with real contact information
-- ═══════════════════════════════════════════════════════════════════
 
INSERT INTO contact_information (role, display_name, phone, whatsapp, email, display_order, is_emergency)
VALUES
  ('Groom',              'Sriram',                '+91 XXXXX XXXXX', '+91XXXXXXXXXX', NULL,                       1, false),
  ('Bride',              'Ramani',                '+91 XXXXX XXXXX', '+91XXXXXXXXXX', NULL,                       2, false),
  ('Groom''s Family',   'Groom''s Father',       '+91 XXXXX XXXXX', '+91XXXXXXXXXX', NULL,                       3, false),
  ('Bride''s Family',   'Bride''s Father',        '+91 XXXXX XXXXX', '+91XXXXXXXXXX', NULL,                       4, false),
  ('Wedding Coordinator','Coordinator Name',      '+91 XXXXX XXXXX', '+91XXXXXXXXXX', 'coordinator@example.com',  5, false),
  ('Emergency Contact',  'Emergency - Any Help',  '+91 XXXXX XXXXX', '+91XXXXXXXXXX', NULL,                       6, true)
ON CONFLICT DO NOTHING;
 
-- ═══════════════════════════════════════════════════════════════════
-- USEFUL QUERIES FOR ADMIN / REPORTING
-- ═══════════════════════════════════════════════════════════════════
 
-- RSVP summary
-- SELECT attending, COUNT(*) as rsvps, SUM(guests_count) as total_guests,
--        array_agg(DISTINCT meal_preference) FILTER (WHERE attending=true) as meals
-- FROM rsvps GROUP BY attending;
 
-- Meal preference breakdown (attending only)
-- SELECT meal_preference, COUNT(*) as count
-- FROM rsvps WHERE attending = true
-- GROUP BY meal_preference ORDER BY count DESC;
 
-- Recent blessings
-- SELECT name, relation, message, created_at FROM blessings
-- WHERE is_approved = true ORDER BY created_at DESC LIMIT 20;
 
-- Admin activity log
-- SELECT admin_email, action, target_type, details, created_at
-- FROM admin_logs ORDER BY created_at DESC LIMIT 50;
 