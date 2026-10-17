-- Additive schema 13 -> 14. Existing account and factor state is unchanged.
CREATE TABLE auth_assisted_recovery (
    selector text PRIMARY KEY,
    subject_id uuid NOT NULL UNIQUE REFERENCES auth_subjects(id),
    actor_id uuid NOT NULL REFERENCES auth_subjects(id),
    key_id text NOT NULL,
    secret_digest bytea NOT NULL CHECK (octet_length(secret_digest) = 32),
    security_version bigint NOT NULL CHECK (security_version > 0),
    scope varchar(64) NOT NULL DEFAULT '',
    target_version bigint NOT NULL CHECK (target_version > 0),
    owner_cli boolean NOT NULL DEFAULT false,
    old_email text NOT NULL CHECK (old_email <> ''),
    new_email text NOT NULL CHECK (new_email <> '' AND new_email <> old_email),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '15 minutes'),
    CHECK ((actor_id = subject_id) = owner_cli)
);
CREATE INDEX auth_assisted_recovery_expiry_idx ON auth_assisted_recovery(expires_at);
