-- +goose Up
CREATE TABLE IF NOT EXISTS auth_subjects
(
    id                 BIGSERIAL PRIMARY KEY,
    subject_id         UUID         NOT NULL,
    kind               VARCHAR(32)  NOT NULL,
    public_id          UUID         NOT NULL,
    email              VARCHAR(255) NOT NULL,
    username           VARCHAR(255)          DEFAULT NULL,
    name               VARCHAR(255)          DEFAULT NULL,
    last_name          VARCHAR(255)          DEFAULT NULL,
    father_name        VARCHAR(255)          DEFAULT NULL,
    gender             INTEGER               DEFAULT NULL,
    birthday           DATE                  DEFAULT NULL,
    data               JSONB                 DEFAULT NULL,
    confirmed_email_at TIMESTAMPTZ           DEFAULT NULL,
    password_version   BIGINT       NOT NULL DEFAULT 0,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS auth_subjects_subject_id_idx ON auth_subjects (subject_id);
CREATE UNIQUE INDEX IF NOT EXISTS auth_subjects_public_id_idx ON auth_subjects (public_id);
CREATE UNIQUE INDEX IF NOT EXISTS auth_subjects_email_idx ON auth_subjects (email);
CREATE INDEX IF NOT EXISTS auth_subjects_kind_idx ON auth_subjects (kind);

-- +goose Down
DROP INDEX IF EXISTS auth_subjects_kind_idx;
DROP INDEX IF EXISTS auth_subjects_email_idx;
DROP INDEX IF EXISTS auth_subjects_public_id_idx;
DROP INDEX IF EXISTS auth_subjects_subject_id_idx;
DROP TABLE IF EXISTS auth_subjects;
