-- +goose Up
CREATE TABLE IF NOT EXISTS auth_password_reset_tokens
(
    email      VARCHAR(255) PRIMARY KEY,
    subject_id UUID         NOT NULL REFERENCES auth_subjects (subject_id) ON DELETE CASCADE,
    token      TEXT         NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS auth_password_reset_tokens_token_idx ON auth_password_reset_tokens (token);

-- +goose Down
DROP INDEX IF EXISTS auth_password_reset_tokens_token_idx;
DROP TABLE IF EXISTS auth_password_reset_tokens;
