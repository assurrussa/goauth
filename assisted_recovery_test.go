package goauth //nolint:testpackage // Exercises private invitation snapshot validation.

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	assistedTestOldEmail      = "old@example.test"
	assistedTestCompletionURL = "https://example.test/recover"
)

func TestAssistedRecoverySnapshotRejectsStaleAndMalformedState(t *testing.T) {
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	subject, actor := NewSubjectID(), NewSubjectID()
	account := Account{
		Subject:      Subject{ID: subject, Status: SubjectStatusActive, SecurityVersion: 7},
		PrimaryEmail: Identifier{NormalizedValue: assistedTestOldEmail},
	}
	digest := SecretDigest{KeyID: "test", Digest: bytes.Repeat([]byte{2}, 32)}
	valid := AssistedRecoveryRecord{
		Selector: "selector", SubjectID: subject, ActorID: actor, Digest: digest,
		SecurityVersion: 7, TargetVersion: 7, OldEmail: assistedTestOldEmail, NewEmail: "new@example.test",
		CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
	if !validAssistedRecoveryRecord(valid, account, digest, now) {
		t.Fatal("valid record denied")
	}
	for _, test := range []struct {
		name   string
		mutate func(*AssistedRecoveryRecord)
	}{
		{"subject", func(r *AssistedRecoveryRecord) { r.SubjectID = actor }},
		{"actor", func(r *AssistedRecoveryRecord) { r.ActorID = NilSubjectID }},
		{"security version", func(r *AssistedRecoveryRecord) { r.SecurityVersion-- }},
		{"target version", func(r *AssistedRecoveryRecord) { r.TargetVersion = 0 }},
		{"old email", func(r *AssistedRecoveryRecord) { r.OldEmail = "other@example.test" }},
		{"same email", func(r *AssistedRecoveryRecord) { r.NewEmail = r.OldEmail }},
		{"deadline", func(r *AssistedRecoveryRecord) { r.ExpiresAt = now }},
		{"future issue", func(r *AssistedRecoveryRecord) { r.CreatedAt = now.Add(time.Second) }},
		{
			"unbounded lifetime",
			func(r *AssistedRecoveryRecord) { r.ExpiresAt = r.CreatedAt.Add(AssistedRecoveryLifetime + time.Second) },
		},
		{"key", func(r *AssistedRecoveryRecord) { r.Digest.KeyID = "other" }},
		{"digest", func(r *AssistedRecoveryRecord) {
			r.Digest = SecretDigest{KeyID: "test", Digest: bytes.Repeat([]byte{3}, 32)}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := valid
			test.mutate(&record)
			if validAssistedRecoveryRecord(record, account, digest, now) {
				t.Fatal("invalid record accepted")
			}
		})
	}
	account.Subject.Status = SubjectStatusSuspended
	if validAssistedRecoveryRecord(valid, account, digest, now) {
		t.Fatal("inactive account accepted")
	}
}

func TestAssistedRecoveryRequiresAuditableIndependentVerification(t *testing.T) {
	for _, pair := range [][2]string{
		{"", "reference"},
		{"reason", ""},
		{"reason\nsecret", "reference"},
		{"reason", "reference\x00"},
	} {
		if validAssistedRecoveryReason(pair[0], pair[1]) {
			t.Fatal("invalid reason/reference accepted")
		}
	}
	if !validAssistedRecoveryReason("Lost access to password and prior mailbox", "Verified on established support call #42") {
		t.Fatal("valid attestation denied")
	}
	if _, err := NewAssistedRecovery(nil, nil, assistedTestCompletionURL); !errors.Is(err,
		ErrAssistedRecoveryUnavailable) {
		t.Fatal(err)
	}
}

type assistedConfigStore struct {
	RuntimeStore
	AssistedRecoveryStore
}

type assistedConfigTransaction struct{ AuthTransaction }

func (assistedConfigTransaction) InOwnedAuthTransaction(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

type assistedConfigAuthorization struct{}

func (assistedConfigAuthorization) AuthorizeAssistedRecovery(
	context.Context, AuthContext, SubjectID, string, string,
) error {
	return nil
}

func TestAssistedRecoveryConfigurationAndEarlyDenials(t *testing.T) {
	policy := assistedConfigAuthorization{}
	r := &Runtime{store: assistedConfigStore{}, authTransaction: assistedConfigTransaction{}}
	for _, test := range []struct {
		name          string
		runtime       *Runtime
		authorization AssistedRecoveryAuthorization
		endpoint      string
	}{
		{"nil runtime", nil, policy, assistedTestCompletionURL},
		{"nil authorization", r, nil, assistedTestCompletionURL},
		{"disabled delivery", &Runtime{notificationDelivery: NotificationDeliveryDisabled}, policy, assistedTestCompletionURL},
		{"unsupported store", &Runtime{}, policy, assistedTestCompletionURL},
		{"unmanaged transaction", &Runtime{store: assistedConfigStore{}}, policy, assistedTestCompletionURL},
		{"unsafe URL", r, policy, "https://user:secret@example.test/recover"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewAssistedRecovery(test.runtime, test.authorization, test.endpoint); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
	service, err := NewAssistedRecovery(r, policy, assistedTestCompletionURL)
	if err != nil {
		t.Fatal(err)
	}
	target := struct{ AssistedRecoveryTarget }{}
	for _, scope := range []string{"", " leading", strings.Repeat("s", 65)} {
		_, err := NewScopedAssistedRecovery(r, policy, assistedTestCompletionURL, scope, target)
		if !errors.Is(err, ErrAssistedRecoveryUnavailable) {
			t.Fatal(err)
		}
	}
	_, err = NewScopedAssistedRecovery(r, policy, assistedTestCompletionURL, "scope", nil)
	if !errors.Is(err, ErrAssistedRecoveryUnavailable) {
		t.Fatal(err)
	}
	if _, err := NewScopedAssistedRecovery(nil, policy, assistedTestCompletionURL, "scope", target); err == nil {
		t.Fatal("nil runtime accepted")
	}
	scoped, err := NewScopedAssistedRecovery(r, policy, assistedTestCompletionURL, "fixed-scope", target)
	if err != nil || scoped.scope != "fixed-scope" {
		t.Fatal("valid scope rejected", err)
	}
	if err := service.Initiate(t.Context(), AssistedRecoveryRequest{}); !errors.Is(err, ErrAssistedRecoveryDenied) {
		t.Fatal(err)
	}
	if err := service.Complete(t.Context(), AssistedRecoveryCompletion{
		Token: strings.Repeat("x", 1025),
	}); !errors.Is(err, ErrAssistedRecoveryDenied) {
		t.Fatal(err)
	}
	if err := service.InitiateOwner(t.Context(), AssistedRecoveryOwnerRequest{}, nil); !errors.Is(err, ErrAssistedRecoveryDenied) {
		t.Fatal(err)
	}
	if _, err := service.targetSnapshot(t.Context(), Account{}); !errors.Is(err, ErrAssistedRecoveryDenied) {
		t.Fatal(err)
	}
	account := Account{
		Subject:      Subject{SecurityVersion: 7},
		PrimaryEmail: Identifier{ID: "email-id", NormalizedValue: assistedTestOldEmail},
	}
	snapshot, err := service.targetSnapshot(t.Context(), account)
	if err != nil || snapshot.Email != assistedTestOldEmail || snapshot.Version != 7 {
		t.Fatal(snapshot, err)
	}
	for _, owner := range []bool{false, true} {
		if got := ownerCLIString(owner); got != strconv.FormatBool(owner) {
			t.Fatal(got)
		}
	}
}
