-- +goose Up
CREATE TABLE IF NOT EXISTS auth_email_change_requests
(
    id          BIGSERIAL PRIMARY KEY,
    subject_id  UUID         NOT NULL REFERENCES auth_subjects (subject_id) ON DELETE CASCADE,
    old_email   VARCHAR(255) NOT NULL,
    new_email   VARCHAR(255) NOT NULL,
    code        VARCHAR(64)  NOT NULL,
    attempts    INTEGER      NOT NULL DEFAULT 0,
    expires_at  TIMESTAMPTZ  NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS auth_email_change_requests_subject_id_idx
    ON auth_email_change_requests (subject_id);

-- +goose Down
DROP INDEX IF EXISTS auth_email_change_requests_subject_id_idx;
DROP TABLE IF EXISTS auth_email_change_requests;
