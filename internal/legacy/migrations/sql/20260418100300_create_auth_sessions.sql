-- +goose Up
CREATE TABLE IF NOT EXISTS auth_sessions
(
    id               BIGSERIAL PRIMARY KEY,
    subject_id       UUID         NOT NULL REFERENCES auth_subjects (subject_id) ON DELETE CASCADE,
    subject_kind     VARCHAR(32)  NOT NULL,
    token            TEXT         NOT NULL,
    payload          JSONB        DEFAULT NULL,
    password_version BIGINT       NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at       TIMESTAMPTZ  NOT NULL,
    revoked_at       TIMESTAMPTZ  DEFAULT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS auth_sessions_token_idx ON auth_sessions (token);
CREATE INDEX IF NOT EXISTS auth_sessions_subject_id_idx ON auth_sessions (subject_id);
CREATE INDEX IF NOT EXISTS auth_sessions_expires_at_idx ON auth_sessions (expires_at);

-- +goose Down
DROP INDEX IF EXISTS auth_sessions_expires_at_idx;
DROP INDEX IF EXISTS auth_sessions_subject_id_idx;
DROP INDEX IF EXISTS auth_sessions_token_idx;
DROP TABLE IF EXISTS auth_sessions;
