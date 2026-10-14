ALTER TABLE auth_notification_deliveries
    DROP CONSTRAINT auth_notification_deliveries_state_check,
    ADD CONSTRAINT auth_notification_deliveries_state_check
        CHECK (state IN ('pending', 'leased', 'blocked', 'delivered', 'exhausted', 'expired', 'cancelled'));

CREATE INDEX auth_notification_deliveries_receipt_cleanup_idx
    ON auth_notification_deliveries
        ((GREATEST(COALESCE(delivered_at, valid_until), valid_until)), id)
    WHERE state IN ('delivered', 'exhausted', 'expired', 'cancelled')
        AND ciphertext IS NULL AND octet_length(nonce) = 0 AND octet_length(additional_data) = 0
        AND lease_token IS NULL AND leased_until IS NULL;
