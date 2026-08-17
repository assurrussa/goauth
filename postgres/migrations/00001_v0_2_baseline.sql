CREATE TABLE goauth_schema_version (
    version SMALLINT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth_subjects (
    id UUID PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'disabled')),
    security_version BIGINT NOT NULL DEFAULT 1 CHECK (security_version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE auth_identifiers (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL REFERENCES auth_subjects(id) ON DELETE CASCADE,
    scheme TEXT NOT NULL CHECK (scheme ~ '^[a-z][a-z0-9_-]{0,31}$'),
    display_value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    is_primary BOOLEAN NOT NULL DEFAULT false,
    verified_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (scheme, normalized_value)
);

CREATE UNIQUE INDEX auth_identifiers_subject_primary_scheme_uidx
    ON auth_identifiers (subject_id, scheme)
    WHERE is_primary;
CREATE INDEX auth_identifiers_subject_idx ON auth_identifiers (subject_id);

CREATE TABLE auth_basic_profiles (
    subject_id UUID PRIMARY KEY REFERENCES auth_subjects(id) ON DELETE CASCADE,
    username TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL DEFAULT '',
    given_name TEXT NOT NULL DEFAULT '',
    family_name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE auth_local_credentials (
    subject_id UUID PRIMARY KEY REFERENCES auth_subjects(id) ON DELETE CASCADE,
    password_phc TEXT NOT NULL CHECK (password_phc LIKE '$argon2id$%'),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE auth_sessions (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL REFERENCES auth_subjects(id) ON DELETE CASCADE,
    realm TEXT NOT NULL CHECK (realm ~ '^[a-z][a-z0-9_-]{0,31}$'),
    scope TEXT NOT NULL CHECK (scope IN ('authenticated', 'confirmation')),
    security_version BIGINT NOT NULL CHECK (security_version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL
);

CREATE INDEX auth_sessions_subject_active_idx
    ON auth_sessions (subject_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE auth_refresh_families (
    id UUID PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
    subject_id UUID NOT NULL REFERENCES auth_subjects(id) ON DELETE CASCADE,
    realm TEXT NOT NULL,
    security_version BIGINT NOT NULL CHECK (security_version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    replayed_at TIMESTAMPTZ NULL
);

CREATE INDEX auth_refresh_families_subject_active_idx
    ON auth_refresh_families (subject_id)
    WHERE revoked_at IS NULL;

CREATE TABLE auth_refresh_tokens (
    selector TEXT PRIMARY KEY,
    family_id UUID NOT NULL REFERENCES auth_refresh_families(id) ON DELETE CASCADE,
    key_id TEXT NOT NULL,
    secret_digest BYTEA NOT NULL CHECK (octet_length(secret_digest) = 32),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    replaced_by_selector TEXT NULL REFERENCES auth_refresh_tokens(selector)
);

CREATE INDEX auth_refresh_tokens_family_idx ON auth_refresh_tokens (family_id);

CREATE TABLE auth_oidc_refresh_families (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL REFERENCES auth_subjects(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    security_version BIGINT NOT NULL CHECK (security_version > 0),
    authenticated_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    replayed_at TIMESTAMPTZ NULL
);

CREATE INDEX auth_oidc_refresh_families_subject_active_idx
    ON auth_oidc_refresh_families (subject_id, client_id)
    WHERE revoked_at IS NULL;

CREATE TABLE auth_oidc_refresh_tokens (
    selector TEXT PRIMARY KEY,
    family_id UUID NOT NULL REFERENCES auth_oidc_refresh_families(id) ON DELETE CASCADE,
    key_id TEXT NOT NULL,
    secret_digest BYTEA NOT NULL CHECK (octet_length(secret_digest) = 32),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    replaced_by_selector TEXT NULL REFERENCES auth_oidc_refresh_tokens(selector)
);

CREATE INDEX auth_oidc_refresh_tokens_family_idx ON auth_oidc_refresh_tokens (family_id);

CREATE TABLE auth_password_reset_records (
    selector TEXT PRIMARY KEY,
    subject_id UUID NOT NULL REFERENCES auth_subjects(id) ON DELETE CASCADE,
    key_id TEXT NOT NULL,
    secret_digest BYTEA NOT NULL CHECK (octet_length(secret_digest) = 32),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL
);

CREATE INDEX auth_password_reset_subject_idx
    ON auth_password_reset_records (subject_id, created_at DESC);

CREATE TABLE auth_email_challenges (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL REFERENCES auth_subjects(id) ON DELETE CASCADE,
    identifier_id UUID NOT NULL REFERENCES auth_identifiers(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    key_id TEXT NOT NULL,
    code_digest BYTEA NOT NULL CHECK (octet_length(code_digest) = 32),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ NULL
);

CREATE INDEX auth_email_challenges_subject_latest_idx
    ON auth_email_challenges (subject_id, purpose, created_at DESC);

CREATE TABLE auth_email_change_records (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL REFERENCES auth_subjects(id) ON DELETE CASCADE,
    new_display_value TEXT NOT NULL,
    new_normalized_value TEXT NOT NULL,
    key_id TEXT NOT NULL,
    code_digest BYTEA NOT NULL CHECK (octet_length(code_digest) = 32),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX auth_email_change_active_value_uidx
    ON auth_email_change_records (new_normalized_value)
    WHERE consumed_at IS NULL;

CREATE TABLE auth_identity_links (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL REFERENCES auth_subjects(id) ON DELETE CASCADE,
    issuer TEXT NOT NULL,
    external_subject TEXT NOT NULL,
    email_normalized TEXT NOT NULL DEFAULT '',
    email_verified BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (issuer, external_subject)
);

CREATE INDEX auth_identity_links_subject_idx ON auth_identity_links (subject_id);

CREATE TABLE auth_permissions (
    id BIGSERIAL PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    permission_key TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth_roles (
    id BIGSERIAL PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_system BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth_role_permissions (
    role_id BIGINT NOT NULL REFERENCES auth_roles(id) ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES auth_permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE auth_subject_roles (
    subject_id UUID NOT NULL REFERENCES auth_subjects(id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES auth_roles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (subject_id, role_id)
);

CREATE TABLE auth_rate_limit_events (
    id BIGSERIAL PRIMARY KEY,
    subject_id UUID NULL REFERENCES auth_subjects(id) ON DELETE CASCADE,
    key_id TEXT NOT NULL,
    bucket_digest BYTEA NOT NULL CHECK (octet_length(bucket_digest) = 32),
    action TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX auth_rate_limit_events_window_idx
    ON auth_rate_limit_events (key_id, bucket_digest, action, occurred_at DESC);

CREATE TABLE auth_security_audit_events (
    id UUID PRIMARY KEY,
    subject_id UUID NULL REFERENCES auth_subjects(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    realm TEXT NOT NULL DEFAULT '',
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX auth_security_audit_events_subject_idx
    ON auth_security_audit_events (subject_id, occurred_at DESC);

INSERT INTO goauth_schema_version (version) VALUES (2);
