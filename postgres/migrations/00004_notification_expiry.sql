CREATE INDEX auth_notification_deliveries_expiry_idx
    ON auth_notification_deliveries (valid_until, id)
    WHERE ciphertext IS NOT NULL;
