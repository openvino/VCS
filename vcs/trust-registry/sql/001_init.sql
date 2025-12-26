-- =========================================================
-- Trust Registry schema (v1)
-- =========================================================

-- Subject types:
-- wallet   : end-user wallet
-- issuer   : credential issuer
-- verifier : credential verifier / relying party
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'trust_subject_type') THEN
    CREATE TYPE trust_subject_type AS ENUM ('wallet', 'issuer', 'verifier');
  END IF;
END $$;

-- WARNING: This drops the old table (data loss).
DROP TABLE IF EXISTS trust_entries;

CREATE TABLE trust_entries (
  -- "select trusted, reason from trust_entries where did=$1"
  did text PRIMARY KEY,

  subject_type trust_subject_type NOT NULL DEFAULT 'wallet',
  domain text,

  trusted boolean NOT NULL DEFAULT false,
  reason text,

  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);

CREATE INDEX trust_entries_updated_at_idx ON trust_entries(updated_at);

-- Optional: trust entities by domain:
CREATE INDEX trust_entries_domain_idx ON trust_entries(domain);

-- Automatically maintain updated_at on updates.
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS trigger AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trust_entries_set_updated_at ON trust_entries;

CREATE TRIGGER trust_entries_set_updated_at
BEFORE UPDATE ON trust_entries
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
