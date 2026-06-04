package adminsession

import (
	"context"
	"errors"
	"fmt"
	"time"

	authcore "github.com/assurrussa/goauth/core"
	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
	"github.com/assurrussa/goauth/local/emailchange"
	"github.com/assurrussa/goauth/local/passwordchange"
	"github.com/assurrussa/goauth/local/passwordreset"
	"github.com/assurrussa/goauth/session/adminaccount"
)

type OutboxPutter interface {
	Put(ctx context.Context, name, payload string, availableAt time.Time) (outbox.JobID, error)
}

type Options struct {
	Reader          authcore.SubjectReader
	Lookup          authcore.SubjectLookup
	Writer          authcore.SubjectWriter
	PasswordResets  authcore.PasswordResetStore
	Hasher          authcore.PasswordHasher
	Tx              authcore.TxManager
	Outbox          OutboxPutter
	BaseURL         string
	ResetTTLMinutes int
	EmailStore      emailchange.Store
	EmailRepo       emailchange.EmailRepository
	Invalidator     passwordreset.Invalidator
}

type Kit struct {
	PasswordReset  *passwordreset.Service
	PasswordChange *passwordchange.Service
	EmailChange    *emailchange.Service
	Account        *adminaccount.Service
}

func New(opts Options) (*Kit, error) {
	switch {
	case opts.Reader == nil:
		return nil, errors.New("adminsession: reader is required")
	case opts.Lookup == nil:
		return nil, errors.New("adminsession: lookup is required")
	case opts.Writer == nil:
		return nil, errors.New("adminsession: writer is required")
	case opts.PasswordResets == nil:
		return nil, errors.New("adminsession: password reset store is required")
	case opts.Hasher == nil:
		return nil, errors.New("adminsession: hasher is required")
	case opts.Tx == nil:
		return nil, errors.New("adminsession: tx manager is required")
	case opts.Outbox == nil:
		return nil, errors.New("adminsession: outbox is required")
	case opts.EmailStore == nil:
		return nil, errors.New("adminsession: email change store is required")
	case opts.EmailRepo == nil:
		return nil, errors.New("adminsession: email repository is required")
	}

	if opts.ResetTTLMinutes <= 0 {
		opts.ResetTTLMinutes = 60
	}

	passwordResetService, err := passwordreset.New(passwordreset.Options{
		Reader:      opts.Reader,
		Writer:      opts.Writer,
		Tokens:      opts.PasswordResets,
		Hasher:      opts.Hasher,
		Tx:          opts.Tx,
		Outbox:      opts.Outbox,
		BaseURL:     opts.BaseURL,
		TTLMinutes:  opts.ResetTTLMinutes,
		Invalidator: opts.Invalidator,
	})
	if err != nil {
		return nil, fmt.Errorf("adminsession: build password reset service: %w", err)
	}

	passwordChangeService, err := passwordchange.New(passwordchange.Options{
		Lookup: opts.Lookup,
		Writer: opts.Writer,
		Hasher: opts.Hasher,
		Tx:     opts.Tx,
		Outbox: opts.Outbox,
	})
	if err != nil {
		return nil, fmt.Errorf("adminsession: build password change service: %w", err)
	}

	emailChangeService, err := emailchange.New(emailchange.Options{
		Store:  opts.EmailStore,
		Repo:   opts.EmailRepo,
		Outbox: opts.Outbox,
	})
	if err != nil {
		return nil, fmt.Errorf("adminsession: build email change service: %w", err)
	}

	accountService, err := adminaccount.New(adminaccount.Options{
		Lookup:       opts.Lookup,
		Reset:        passwordResetService,
		Change:       passwordChangeService,
		EmailChanges: emailChangeAdapter{service: emailChangeService},
		Tx:           opts.Tx,
	})
	if err != nil {
		return nil, fmt.Errorf("adminsession: build account service: %w", err)
	}

	return &Kit{
		PasswordReset:  passwordResetService,
		PasswordChange: passwordChangeService,
		EmailChange:    emailChangeService,
		Account:        accountService,
	}, nil
}

type emailChangeAdapter struct {
	service *emailchange.Service
}

func (a emailChangeAdapter) Request(
	ctx context.Context,
	subject adminaccount.Subject[int64],
	newEmail,
	clientIP string,
) error {
	return a.service.Request(ctx, adminSubject(subject), newEmail, clientIP)
}

func (a emailChangeAdapter) Confirm(ctx context.Context, subject adminaccount.Subject[int64], code string) (string, error) {
	return a.service.Confirm(ctx, adminSubject(subject), code)
}

func (a emailChangeAdapter) GetPending(
	ctx context.Context,
	subject adminaccount.Subject[int64],
) (*adminaccount.Pending, error) {
	pending, err := a.service.GetPending(ctx, adminSubject(subject).CanonicalID())
	if err != nil || pending == nil {
		return nil, err
	}

	return &adminaccount.Pending{
		NewEmail:  pending.NewEmail,
		ExpiresAt: pending.ExpiresAt,
	}, nil
}

func adminSubject(subject adminaccount.Subject[int64]) authcore.Subject {
	return authcore.Subject{
		ID:        subject.CanonicalID,
		Kind:      authcore.SubjectKindAccount,
		Email:     subject.Email,
		NumericID: subject.ID,
		Name:      subject.Name,
	}
}
