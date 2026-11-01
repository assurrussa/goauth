ALTER TABLE auth_notification_deliveries
 ADD COLUMN transport_protocol varchar(64) NOT NULL DEFAULT '',
 ADD CONSTRAINT auth_notification_transport_protocol_check CHECK (transport_protocol ~ '^[A-Za-z0-9_-]{0,64}$'),
 ADD COLUMN gateway_receipt_id varchar(128),
 ADD COLUMN gateway_accepted_at timestamptz,
 DROP CONSTRAINT auth_notification_deliveries_state_check,
 ADD CONSTRAINT auth_notification_deliveries_state_check
 CHECK (state IN ('pending','leased','blocked','delivered','exhausted','expired','cancelled','gateway_accepted')),
 ADD CONSTRAINT auth_notification_gateway_receipt_check CHECK (
 (gateway_receipt_id IS NULL AND gateway_accepted_at IS NULL AND state <> 'gateway_accepted') OR
 (gateway_receipt_id IS NOT NULL AND gateway_receipt_id ~ '^[A-Za-z0-9_.:-]{1,128}$'
 AND gateway_accepted_at IS NOT NULL AND ciphertext IS NULL AND octet_length(nonce)=0
 AND octet_length(additional_data)=0 AND state IN ('gateway_accepted','leased','delivered','exhausted','expired')));
CREATE INDEX auth_notification_gateway_ready_idx ON auth_notification_deliveries(next_attempt_at,created_at)
 WHERE gateway_receipt_id IS NOT NULL AND state IN ('gateway_accepted','leased');
