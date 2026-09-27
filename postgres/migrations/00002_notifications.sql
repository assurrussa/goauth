CREATE TABLE goauth_migration_history (
    version SMALLINT PRIMARY KEY,
    checksum TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth_notification_deliveries (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL REFERENCES auth_subjects(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    reference_id TEXT NOT NULL DEFAULT '',
    valid_until TIMESTAMPTZ NOT NULL,
    key_id TEXT NOT NULL,
    nonce BYTEA NOT NULL,
    ciphertext BYTEA NULL,
    additional_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    delete_after TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'leased', 'blocked', 'delivered', 'exhausted', 'expired')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL,
    lease_token UUID NULL,
    leased_until TIMESTAMPTZ NULL,
    delivered_at TIMESTAMPTZ NULL,
    last_failure TEXT NULL,
    CHECK (valid_until <= delete_after),
    CHECK (state != 'leased' OR (lease_token IS NOT NULL AND leased_until IS NOT NULL))
);

CREATE INDEX auth_notification_deliveries_ready_idx
    ON auth_notification_deliveries (next_attempt_at, created_at)
    WHERE state IN ('pending', 'blocked', 'leased');
CREATE INDEX auth_notification_deliveries_retention_idx
    ON auth_notification_deliveries (delete_after);
