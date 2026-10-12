CREATE TABLE auth_mfa_factors (
 subject_id uuid PRIMARY KEY REFERENCES auth_subjects(id) ON DELETE CASCADE,
 factor_id text NOT NULL CHECK (length(factor_id) BETWEEN 1 AND 128),
 revision bigint NOT NULL CHECK (revision > 0),
 enabled boolean NOT NULL DEFAULT false,
 key_id text NOT NULL DEFAULT '' CHECK (length(key_id) <= 64),
 secret bytea NOT NULL DEFAULT '',
 last_step bigint NOT NULL DEFAULT -1 CHECK (last_step >= -1),
 CHECK ((enabled AND key_id <> '' AND octet_length(secret) >= 28) OR
        (NOT enabled AND key_id = '' AND octet_length(secret) = 0))
);
CREATE TABLE auth_mfa_recovery (
 subject_id uuid NOT NULL REFERENCES auth_mfa_factors(subject_id) ON DELETE CASCADE,
 digest bytea NOT NULL CHECK (octet_length(digest) = 32),
 PRIMARY KEY (subject_id, digest)
);
CREATE TABLE auth_mfa_budget (
 subject_id uuid PRIMARY KEY REFERENCES auth_subjects(id) ON DELETE CASCADE,
 window_at timestamptz NOT NULL,
 attempts integer NOT NULL CHECK (attempts BETWEEN 1 AND 10)
);
CREATE TABLE auth_mfa_pending (
 id text PRIMARY KEY CHECK (length(id) = 43),
 subject_id uuid NOT NULL REFERENCES auth_mfa_factors(subject_id) ON DELETE CASCADE,
 realm text NOT NULL CHECK (realm ~ '^[a-z][a-z0-9_-]{0,31}$'),
 security_version bigint NOT NULL CHECK (security_version > 0),
 factor_id text NOT NULL,
 factor_revision bigint NOT NULL CHECK (factor_revision > 0),
 binding bytea NOT NULL CHECK (octet_length(binding) = 32),
 authenticated_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 UNIQUE (subject_id, realm),
 CHECK (expires_at > authenticated_at AND expires_at <= authenticated_at + interval '3 minutes')
);
CREATE INDEX auth_mfa_pending_expiry_idx ON auth_mfa_pending(expires_at);
CREATE TABLE auth_mfa_enrollments (
 subject_id uuid PRIMARY KEY REFERENCES auth_mfa_factors(subject_id) ON DELETE CASCADE,
 id text NOT NULL CHECK (length(id) = 43),
 revision bigint NOT NULL CHECK (revision > 0),
 security_version bigint NOT NULL CHECK (security_version > 0),
 session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
 binding bytea NOT NULL CHECK (octet_length(binding) = 32),
 key_id text NOT NULL CHECK (length(key_id) BETWEEN 1 AND 64),
 secret bytea NOT NULL CHECK (octet_length(secret) >= 28),
 created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes')
);
CREATE INDEX auth_mfa_enrollments_expiry_idx ON auth_mfa_enrollments(expires_at);
