package adminaccount_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	"github.com/assurrussa/goauth/internal/legacy/session/adminaccount"
)

type resetStub struct {
	requestEmail string
	perform      struct {
		email    string
		token    string
		password string
	}
}

func (s *resetStub) Request(_ context.Context, email string) error {
	s.requestEmail = email
	return nil
}

func (s *resetStub) Perform(_ context.Context, email, token, password string) error {
	s.perform.email = email
	s.perform.token = token
	s.perform.password = password
	return nil
}

type changeStub struct {
	subjectID       authcore.SubjectID
	currentPassword string
	newPassword     string
}

func (s *changeStub) Change(
	_ context.Context,
	subjectID authcore.SubjectID,
	currentPassword, newPassword string,
) error {
	s.subjectID = subjectID
	s.currentPassword = currentPassword
	s.newPassword = newPassword
	return nil
}

type txStub struct {
	calls int
}

func (s *txStub) RunInTx(ctx context.Context, fn func(ctx context.Context) error) error {
	s.calls++
	return fn(ctx)
}

type lookupStub struct {
	subject authcore.Subject
}

func (s *lookupStub) GetByID(_ context.Context, _ authcore.SubjectID) (authcore.Subject, error) {
	return s.subject, nil
}

type emailChangeStub struct {
	request struct {
		subject  adminaccount.Subject[int64]
		newEmail string
		clientIP string
	}
	confirm struct {
		subject adminaccount.Subject[int64]
		code    string
	}
	pending *adminaccount.Pending
}

func (s *emailChangeStub) Request(
	_ context.Context,
	subject adminaccount.Subject[int64],
	newEmail, clientIP string,
) error {
	s.request.subject = subject
	s.request.newEmail = newEmail
	s.request.clientIP = clientIP
	return nil
}

func (s *emailChangeStub) Confirm(
	_ context.Context,
	subject adminaccount.Subject[int64],
	code string,
) (string, error) {
	s.confirm.subject = subject
	s.confirm.code = code
	return "updated@example.com", nil
}

func (s *emailChangeStub) GetPending(_ context.Context, _ adminaccount.Subject[int64]) (*adminaccount.Pending, error) {
	return s.pending, nil
}

func TestService(t *testing.T) {
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174000")
	resetSvc := &resetStub{}
	changeSvc := &changeStub{}
	tx := &txStub{}
	lookup := &lookupStub{
		subject: authcore.Subject{
			ID:        subjectID,
			Kind:      authcore.SubjectKindAdmin,
			NumericID: 123,
			Email:     "admin@example.com",
			Name:      "Admin",
		},
	}
	emailSvc := &emailChangeStub{
		pending: &adminaccount.Pending{
			NewEmail:  "pending@example.com",
			ExpiresAt: time.Now().Add(time.Minute),
		},
	}

	service, err := adminaccount.New(adminaccount.Options{
		Lookup:       lookup,
		Reset:        resetSvc,
		Change:       changeSvc,
		EmailChanges: emailSvc,
		Tx:           tx,
	})
	require.NoError(t, err)

	err = service.RequestPasswordReset(context.Background(), "admin@example.com")
	require.NoError(t, err)
	assert.Equal(t, "admin@example.com", resetSvc.requestEmail)

	err = service.PerformPasswordReset(context.Background(), "admin@example.com", "token", "password")
	require.NoError(t, err)
	assert.Equal(t, "token", resetSvc.perform.token)

	err = service.ChangePassword(context.Background(), subjectID, "current", "new")
	require.NoError(t, err)
	assert.Equal(t, subjectID, changeSvc.subjectID)

	err = service.RequestEmailChange(context.Background(), subjectID, "next@example.com", "127.0.0.1")
	require.NoError(t, err)
	assert.Equal(t, 1, tx.calls)
	assert.Equal(t, "next@example.com", emailSvc.request.newEmail)
	assert.Equal(t, subjectID, emailSvc.request.subject.CanonicalID)

	newEmail, err := service.ConfirmEmailChange(context.Background(), subjectID, "123456")
	require.NoError(t, err)
	assert.Equal(t, 2, tx.calls)
	assert.Equal(t, "updated@example.com", newEmail)
	assert.Equal(t, subjectID, emailSvc.confirm.subject.CanonicalID)

	pending, err := service.GetPendingEmailChange(context.Background(), subjectID)
	require.NoError(t, err)
	require.NotNil(t, pending)
	assert.Equal(t, "pending@example.com", pending.NewEmail)
}
