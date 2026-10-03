ALTER TABLE auth_local_credentials
    ADD COLUMN password_input_policy TEXT NOT NULL DEFAULT 'unicode_v1'
    CHECK (password_input_policy IN ('unicode_v1', 'legacy_bytes_256'));
