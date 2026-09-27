-- +goose Up
CREATE TABLE IF NOT EXISTS auth_external_identities
(
    id               BIGSERIAL PRIMARY KEY,
    subject_id       UUID         NOT NULL REFERENCES auth_subjects (subject_id) ON DELETE CASCADE,
    issuer           VARCHAR(255) NOT NULL,
    external_subject VARCHAR(255) NOT NULL,
    auth_source      VARCHAR(64)  NOT NULL,
    email            VARCHAR(255) DEFAULT NULL,
    email_verified   BOOLEAN      DEFAULT NULL,
    last_seen_at     TIMESTAMPTZ  NOT NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS auth_external_identities_external_idx
    ON auth_external_identities (issuer, external_subject);
CREATE INDEX IF NOT EXISTS auth_external_identities_subject_id_idx
    ON auth_external_identities (subject_id);

-- +goose Down
DROP INDEX IF EXISTS auth_external_identities_subject_id_idx;
DROP INDEX IF EXISTS auth_external_identities_external_idx;
DROP TABLE IF EXISTS auth_external_identities;
