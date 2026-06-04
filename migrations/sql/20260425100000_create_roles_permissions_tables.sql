-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS roles
(
    id          BIGSERIAL PRIMARY KEY,
    uuid        uuid                       NOT NULL,
    slug        VARCHAR(100)               NOT NULL,
    name        VARCHAR(255)               NOT NULL,
    description TEXT                       DEFAULT NULL,
    is_system   BOOLEAN                    DEFAULT FALSE NOT NULL,
    created_at  TIMESTAMPTZ                DEFAULT NOW() NOT NULL,
    updated_at  TIMESTAMPTZ                DEFAULT NOW() NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS roles_uuid_idx ON roles (uuid);
CREATE UNIQUE INDEX IF NOT EXISTS roles_slug_idx ON roles (slug);

CREATE TABLE IF NOT EXISTS permissions
(
    id          BIGSERIAL PRIMARY KEY,
    uuid        uuid                       NOT NULL,
    domain      VARCHAR(100)               NOT NULL,
    action      VARCHAR(100)               NOT NULL,
    description TEXT                       DEFAULT NULL,
    created_at  TIMESTAMPTZ                DEFAULT NOW() NOT NULL,
    updated_at  TIMESTAMPTZ                DEFAULT NOW() NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS permissions_uuid_idx ON permissions (uuid);
CREATE UNIQUE INDEX IF NOT EXISTS permissions_domain_action_idx ON permissions (domain, action);

CREATE TABLE IF NOT EXISTS role_permissions
(
    role_id       BIGINT NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS role_hierarchy
(
    parent_role_id BIGINT NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    child_role_id  BIGINT NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    created_at     TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    PRIMARY KEY (parent_role_id, child_role_id),
    CONSTRAINT role_hierarchy_no_self_reference CHECK (parent_role_id <> child_role_id)
);

CREATE TABLE IF NOT EXISTS auth_subject_roles
(
    subject_id UUID        NOT NULL REFERENCES auth_subjects (subject_id) ON DELETE CASCADE,
    role_id    BIGINT       NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ  DEFAULT NOW() NOT NULL,
    PRIMARY KEY (subject_id, role_id)
);

CREATE INDEX IF NOT EXISTS auth_subject_roles_subject_id_idx ON auth_subject_roles (subject_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS auth_subject_roles;
DROP TABLE IF EXISTS role_hierarchy;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
-- +goose StatementEnd
