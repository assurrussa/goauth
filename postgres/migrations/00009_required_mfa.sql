ALTER TABLE auth_sessions ADD COLUMN mfa_admission text NOT NULL DEFAULT 'unknown'
 CONSTRAINT auth_sessions_mfa_admission_check CHECK (mfa_admission IN ('unknown','factor','external'));

ALTER TABLE auth_mfa_pending
 ADD COLUMN kind text NOT NULL DEFAULT 'factor',
 ADD COLUMN setup_id text NOT NULL DEFAULT '',
 ADD COLUMN setup_key_id text NOT NULL DEFAULT '',
 ADD COLUMN setup_secret bytea NOT NULL DEFAULT '',
 ADD COLUMN setup_recovery bytea NOT NULL DEFAULT '',
 ADD CONSTRAINT auth_mfa_pending_kind_check CHECK (kind IN ('factor','enrollment')),
 ADD CONSTRAINT auth_mfa_pending_setup_check CHECK (
  (setup_id='' AND setup_key_id='' AND octet_length(setup_secret)=0 AND octet_length(setup_recovery)=0)
  OR (kind='enrollment' AND length(setup_id)=43 AND length(setup_key_id) BETWEEN 1 AND 64
      AND octet_length(setup_secret)>=28 AND octet_length(setup_recovery)=320));
