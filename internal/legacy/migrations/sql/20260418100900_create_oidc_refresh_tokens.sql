-- +goose Up
CREATE TABLE IF NOT EXISTS auth_oidc_refresh_tokens
(
    id               BIGSERIAL PRIMARY KEY,
    subject_id       UUID         NOT NULL REFERENCES auth_subjects (subject_id) ON DELETE CASCADE,
    client_id        TEXT         NOT NULL,
    password_version BIGINT       NOT NULL DEFAULT 0,
    token            TEXT         NOT NULL,
    scopes           TEXT         NOT NULL DEFAULT '',
    authenticated_at TIMESTAMPTZ  NOT NULL,
    expires_at       TIMESTAMPTZ  NOT NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    revoked_at       TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS auth_oidc_refresh_tokens_token_idx ON auth_oidc_refresh_tokens (token);
CREATE INDEX IF NOT EXISTS auth_oidc_refresh_tokens_subject_id_idx ON auth_oidc_refresh_tokens (subject_id);
CREATE INDEX IF NOT EXISTS auth_oidc_refresh_tokens_client_id_idx ON auth_oidc_refresh_tokens (client_id);
CREATE INDEX IF NOT EXISTS auth_oidc_refresh_tokens_expires_at_idx ON auth_oidc_refresh_tokens (expires_at);

-- +goose Down
DROP INDEX IF EXISTS auth_oidc_refresh_tokens_expires_at_idx;
DROP INDEX IF EXISTS auth_oidc_refresh_tokens_client_id_idx;
DROP INDEX IF EXISTS auth_oidc_refresh_tokens_subject_id_idx;
DROP INDEX IF EXISTS auth_oidc_refresh_tokens_token_idx;
DROP TABLE IF EXISTS auth_oidc_refresh_tokens;
