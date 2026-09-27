-- +goose Up
CREATE TABLE IF NOT EXISTS auth_refresh_tokens
(
    id               BIGSERIAL PRIMARY KEY,
    subject_id       UUID         NOT NULL REFERENCES auth_subjects (subject_id) ON DELETE CASCADE,
    subject_kind     VARCHAR(32)  NOT NULL,
    token            TEXT         NOT NULL,
    password_version BIGINT       NOT NULL DEFAULT 0,
    reason           TEXT         DEFAULT NULL,
    banned_at        TIMESTAMPTZ  DEFAULT NULL,
    expires_at       TIMESTAMPTZ  NOT NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    revoked_at       TIMESTAMPTZ  DEFAULT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS auth_refresh_tokens_token_idx ON auth_refresh_tokens (token);
CREATE INDEX IF NOT EXISTS auth_refresh_tokens_subject_id_idx ON auth_refresh_tokens (subject_id);
CREATE INDEX IF NOT EXISTS auth_refresh_tokens_expires_at_idx ON auth_refresh_tokens (expires_at);

-- +goose Down
DROP INDEX IF EXISTS auth_refresh_tokens_expires_at_idx;
DROP INDEX IF EXISTS auth_refresh_tokens_subject_id_idx;
DROP INDEX IF EXISTS auth_refresh_tokens_token_idx;
DROP TABLE IF EXISTS auth_refresh_tokens;
