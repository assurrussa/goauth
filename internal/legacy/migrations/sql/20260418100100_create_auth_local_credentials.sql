-- +goose Up
CREATE TABLE IF NOT EXISTS auth_local_credentials
(
    subject_id     UUID PRIMARY KEY REFERENCES auth_subjects (subject_id) ON DELETE CASCADE,
    password_hash  TEXT        NOT NULL,
    password_algo  VARCHAR(64) DEFAULT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- +goose Down
DROP TABLE IF EXISTS auth_local_credentials;
