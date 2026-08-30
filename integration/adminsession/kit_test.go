//nolint:testpackage // internal test
package adminsession

import (
	"context"
	"errors"
	"testing"
	"time"

	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/stretchr/testify/require"

	authcore "github.com/assurrussa/goauth/core"
	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
	"github.com/assurrussa/goauth/local/emailchange"
	authshared "github.com/assurrussa/goauth/shared"
)

func TestKitAccountEmailChangeUsesCanonicalAdminSubjectID(t *testing.T) {
	t.Parallel()

	adminUUID := sharedtypes.NewUserID()
	subjectID := authshared.NewSubjectID()
	emailStore := &emailStoreStub{
		requests: map[string]emailchange.Request{},
	}

	kit, err := New(Options{
		Reader:         subjectReaderStub{},
		Lookup:         subjectLookupStub{subject: authcore.Subject{ID: subjectID, Kind: authcore.SubjectKindAdmin, PublicID: adminUUID, NumericID: 77, Email: "admin@example.com", Name: "Admin"}}, //nolint:lll // autofix
		Writer:         subjectWriterStub{},
		PasswordResets: passwordResetStoreStub{},
		Hasher:         passwordHasherStub{},
		Tx:             txManagerStub{},
		Outbox:         outboxStub{},
		EmailStore:     emailStore,
		EmailRepo:      emailRepoStub{},
	})
	require.NoError(t, err)

	err = kit.Account.RequestEmailChange(context.Background(), subjectID, "next@example.com", "127.0.0.1")
	require.NoError(t, err)
	require.Equal(t, subjectID.String(), emailStore.lastUpsertSubjectID)

	pending, err := kit.Account.GetPendingEmailChange(context.Background(), subjectID)
	require.NoError(t, err)
	require.NotNil(t, pending)
	require.Equal(t, "next@example.com", pending.NewEmail)
}

type subjectReaderStub struct{}

func (subjectReaderStub) GetByEmail(context.Context, string) (authcore.Subject, error) {
	return authcore.Subject{}, nil
}

type subjectLookupStub struct {
	subject authcore.Subject
}

func (s subjectLookupStub) GetByID(_ context.Context, subjectID authcore.SubjectID) (authcore.Subject, error) {
	if s.subject.ID == subjectID {
		return s.subject, nil
	}
	return authcore.Subject{}, nil
}

type subjectWriterStub struct{}

func (subjectWriterStub) CreateUser(_ context.Context, subject authcore.Subject) (authcore.Subject, error) {
	return subject, nil
}

func (subjectWriterStub) UpdatePassword(context.Context, authcore.Subject, string) error {
	return nil
}

type passwordResetStoreStub struct{}

func (passwordResetStoreStub) Upsert(context.Context, authcore.PasswordResetToken) error { return nil }

func (passwordResetStoreStub) GetByEmail(context.Context, string) (authcore.PasswordResetToken, error) {
	return authcore.PasswordResetToken{}, nil
}
func (passwordResetStoreStub) DeleteByEmail(context.Context, string) error { return nil }

type passwordHasherStub struct{}

func (passwordHasherStub) GenerateHash(string) ([]byte, error) { return []byte("hash"), nil }
func (passwordHasherStub) CompareHash(string, string) error    { return errors.New("mismatch") }

type txManagerStub struct{}

func (txManagerStub) RunInTx(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

type outboxStub struct{}

func (outboxStub) Put(context.Context, string, string, time.Time) (outbox.JobID, error) {
	return outbox.NewJobID(), nil
}

type emailStoreStub struct {
	lastUpsertSubjectID string
	requests            map[string]emailchange.Request
}

func (s *emailStoreStub) Upsert(_ context.Context, subjectID string, req emailchange.Request) error {
	s.lastUpsertSubjectID = subjectID
	s.requests[subjectID] = req
	return nil
}

func (s *emailStoreStub) Get(_ context.Context, subjectID string, _ bool) (emailchange.Request, error) {
	req, ok := s.requests[subjectID]
	if !ok {
		return emailchange.Request{}, emailchange.ErrNotFound
	}
	return req, nil
}

func (*emailStoreStub) IncrementAttempts(context.Context, string) error { return nil }
func (s *emailStoreStub) Delete(_ context.Context, subjectID string) error {
	delete(s.requests, subjectID)
	return nil
}

type emailRepoStub struct{}

func (emailRepoStub) GetByEmail(context.Context, string) (authcore.Subject, error) {
	return authcore.Subject{}, nil
}

func (emailRepoStub) UpdateEmail(context.Context, string, string) error { return nil }

func (emailRepoStub) MarkEmailConfirmed(context.Context, string, time.Time) error { return nil }
