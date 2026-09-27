-- +goose Up
CREATE TABLE IF NOT EXISTS auth_confirmation_codes
(
    id                 BIGSERIAL PRIMARY KEY,
    subject_id         UUID         NOT NULL REFERENCES auth_subjects (subject_id) ON DELETE CASCADE,
    code               VARCHAR(32)  NOT NULL,
    confirmation_type  VARCHAR(32)  NOT NULL,
    confirmation_info  VARCHAR(255) NOT NULL,
    purpose            VARCHAR(64)  NOT NULL,
    attempts           INTEGER      NOT NULL DEFAULT 0,
    verified_at        TIMESTAMPTZ  DEFAULT NULL,
    expires_at         TIMESTAMPTZ  NOT NULL,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS auth_confirmation_codes_subject_type_purpose_idx
    ON auth_confirmation_codes (subject_id, confirmation_type, purpose);
CREATE INDEX IF NOT EXISTS auth_confirmation_codes_expires_at_idx
    ON auth_confirmation_codes (expires_at);

-- +goose Down
DROP INDEX IF EXISTS auth_confirmation_codes_expires_at_idx;
DROP INDEX IF EXISTS auth_confirmation_codes_subject_type_purpose_idx;
DROP TABLE IF EXISTS auth_confirmation_codes;
