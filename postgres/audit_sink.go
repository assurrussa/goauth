package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/assurrussa/goauth"
)

func (s *Store) RecordSecurityEvent(ctx context.Context, event goauth.SecurityEvent) error {
	if event.Type == "" || event.At.IsZero() {
		return errors.New("invalid security audit event")
	}
	attributes, err := json.Marshal(event.Attributes)
	if err != nil {
		return fmt.Errorf("encode security audit attributes: %w", err)
	}
	var subjectID any
	if !event.SubjectID.IsZero() {
		subjectID = event.SubjectID
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO auth_security_audit_events (
    id, subject_id, event_type, realm, attributes, occurred_at
)
VALUES ($1, $2, $3, $4, $5, $6)`,
		uuid.NewString(),
		subjectID,
		event.Type,
		event.Realm,
		attributes,
		event.At,
	); err != nil {
		return fmt.Errorf("insert security audit event: %w", err)
	}

	return nil
}

var _ goauth.AuditSink = (*Store)(nil)
