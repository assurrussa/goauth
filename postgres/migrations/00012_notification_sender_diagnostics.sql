-- Add bounded, non-sensitive diagnostics only; legacy receipts remain unknown.
ALTER TABLE auth_notification_deliveries
    ADD COLUMN last_sender_outcome varchar(32),
    ADD COLUMN last_sender_code varchar(64),
    ADD COLUMN last_sender_http_status integer,
    ADD COLUMN last_sender_attempt integer,
    ADD COLUMN last_sender_observed_at timestamptz,
    ADD CONSTRAINT auth_notification_sender_outcome_check CHECK (last_sender_outcome::text IN ('not_sent', 'retryable', 'rejected', 'unknown', 'simulated')),
    ADD CONSTRAINT auth_notification_sender_code_check CHECK (last_sender_code::text IN ('invalid_request', 'context_done', 'expired', 'request_failed', 'invalid_response', 'idempotency_conflict', 'unauthorized', 'endpoint_unavailable', 'request_too_large', 'quota_exceeded', 'simulated', 'dispatching', 'unknown', 'retry', 'failed', 'provider_rejected_temporary', 'provider_rejected', 'dispatch_outcome_unknown', 'dispatch_in_progress', 'dry_run_no_external_delivery', 'recipient_suppressed', 'retry_budget_exhausted')),
    ADD CONSTRAINT auth_notification_sender_http_check CHECK (last_sender_http_status BETWEEN 100 AND 599),
    ADD CONSTRAINT auth_notification_sender_attempt_check CHECK (last_sender_attempt > 0 AND last_sender_attempt <= attempts),
    ADD CONSTRAINT auth_notification_sender_snapshot_check CHECK ((last_sender_outcome IS NULL AND last_sender_code IS NULL AND last_sender_http_status IS NULL AND last_sender_attempt IS NULL AND last_sender_observed_at IS NULL) OR (last_sender_outcome IS NOT NULL AND last_sender_code IS NOT NULL AND last_sender_attempt IS NOT NULL AND last_sender_observed_at IS NOT NULL));
