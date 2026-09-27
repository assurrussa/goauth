-- +goose Up
CREATE TABLE IF NOT EXISTS auth_sso_identity_links
(
    id               BIGSERIAL PRIMARY KEY,
    subject_id       UUID         NOT NULL REFERENCES auth_subjects (subject_id) ON DELETE CASCADE,
    subject_kind     VARCHAR(32)  NOT NULL,
    issuer           VARCHAR(255) NOT NULL,
    external_subject VARCHAR(255) NOT NULL,
    auth_source      VARCHAR(64)  NOT NULL,
    email            VARCHAR(255) DEFAULT NULL,
    email_verified   BOOLEAN      DEFAULT NULL,
    last_seen_at     TIMESTAMPTZ  NOT NULL,
    created_at       TIMESTAMPTZ  NOT NULL,
    updated_at       TIMESTAMPTZ  NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS auth_sso_identity_links_external_idx ON auth_sso_identity_links (issuer, external_subject);
CREATE INDEX IF NOT EXISTS auth_sso_identity_links_subject_idx ON auth_sso_identity_links (subject_id);

-- +goose Down
DROP INDEX IF EXISTS auth_sso_identity_links_subject_idx;
DROP INDEX IF EXISTS auth_sso_identity_links_external_idx;
DROP TABLE IF EXISTS auth_sso_identity_links;
