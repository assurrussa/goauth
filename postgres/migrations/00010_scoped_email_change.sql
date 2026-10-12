ALTER TABLE auth_email_change_records
 ADD COLUMN scope text NOT NULL DEFAULT '',
 ADD COLUMN expected_security_version bigint,
 ADD COLUMN target_version bigint,
 ADD COLUMN old_normalized_value text,
 ADD CONSTRAINT auth_email_change_scope_snapshot CHECK (
  (scope = '' AND expected_security_version IS NULL AND target_version IS NULL AND old_normalized_value IS NULL)
  OR
  (scope ~ '^[a-z0-9_.-]{1,64}$' AND expected_security_version IS NOT NULL AND expected_security_version > 0
   AND target_version IS NOT NULL AND target_version > 0 AND old_normalized_value IS NOT NULL)
 );
CREATE INDEX auth_email_change_scope_pending_idx
 ON auth_email_change_records(subject_id, scope, created_at DESC, id DESC)
 WHERE consumed_at IS NULL;
