-- +goose Up
CREATE TABLE IF NOT EXISTS auth_confirmations
(
    id                 BIGSERIAL PRIMARY KEY,
    subject_id         UUID         NOT NULL REFERENCES auth_subjects (subject_id) ON DELETE CASCADE,
    confirmation_type  VARCHAR(32)  NOT NULL,
    confirmation_info  VARCHAR(255) NOT NULL,
    purpose            VARCHAR(64)  NOT NULL,
    confirmed_at       TIMESTAMPTZ  NOT NULL,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS auth_confirmations_subject_type_purpose_idx
    ON auth_confirmations (subject_id, confirmation_type, purpose);

-- +goose Down
DROP INDEX IF EXISTS auth_confirmations_subject_type_purpose_idx;
DROP TABLE IF EXISTS auth_confirmations;
