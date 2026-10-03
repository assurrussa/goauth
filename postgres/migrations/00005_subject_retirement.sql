ALTER TABLE auth_subjects
    ADD COLUMN retired_at TIMESTAMPTZ NULL;

ALTER TABLE auth_subjects
    ADD CONSTRAINT auth_subjects_retirement_status_check
    CHECK (retired_at IS NULL OR status = 'disabled');
