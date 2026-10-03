CREATE INDEX auth_rate_limit_events_retention_idx
    ON auth_rate_limit_events (occurred_at, id);
