//nolint:testpackage // Store guards and transactional snapshots require internal access.
package testkit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/internal/authclock"
)

const (
	preparedResetPHC       = "prepared"
	resetPreparationCancel = "cancel"
)

func subjectResetRecord(t *testing.T) (*Store, goauth.PasswordResetRecord) {
	t.Helper()
	s := NewStore()
	id := goauth.NewSubjectID()
	now := time.Now().UTC()
	s.accounts[id.String()] = goauth.Account{Subject: goauth.Subject{
		ID: id, Status: goauth.SubjectStatusActive, SecurityVersion: 7,
	}}
	s.passwords[id.String()] = "existing-password-phc"
	return s, goauth.PasswordResetRecord{
		SubjectID: id, Selector: "subject-reset", Digest: goauth.SecretDigest{KeyID: "test", Digest: make([]byte, 32)},
		ExpectedSecurityVersion: 7, CreatedAt: now, ExpiresAt: now.Add(15 * time.Minute),
	}
}

func TestSubjectBoundResetStoreGuardsCurrentCredentialAndVersion(t *testing.T) {
	for _, scenario := range []string{
		"valid email-less", "stale version", "no credential", "empty credential", "disabled", "retired", "email guard",
	} {
		t.Run(scenario, func(t *testing.T) {
			s, record := subjectResetRecord(t)
			key := record.SubjectID.String()
			switch scenario {
			case "stale version":
				record.ExpectedSecurityVersion--
			case "no credential":
				delete(s.passwords, key)
			case "empty credential":
				s.passwords[key] = ""
			case "disabled":
				account := s.accounts[key]
				account.Subject.Status = goauth.SubjectStatusDisabled
				s.accounts[key] = account
			case "retired":
				s.retired[key] = record.CreatedAt
			case "email guard":
				record.ExpectedNormalizedEmail = "alias@example.test"
			}
			err := s.CreatePasswordResetForSubject(t.Context(), record)
			if scenario == "valid email-less" {
				require.NoError(t, err)
				require.Len(t, s.resets, 1)
			} else {
				require.Error(t, err)
				require.Empty(t, s.resets)
			}
		})
	}
}

func TestSubjectBoundResetInvalidationJoinsTransaction(t *testing.T) {
	s, record := subjectResetRecord(t)
	require.NoError(t, s.CreatePasswordResetForSubject(t.Context(), record))
	rollback := errors.New("rollback alias change")
	require.ErrorIs(t, s.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		require.NoError(t, s.InvalidatePasswordResets(ctx, record.SubjectID, record.CreatedAt))
		return rollback
	}), rollback)
	require.Nil(t, s.resets[record.Selector].ConsumedAt)
	require.NoError(t, s.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		return s.InvalidatePasswordResets(ctx, record.SubjectID, record.CreatedAt)
	}))
	require.NotNil(t, s.resets[record.Selector].ConsumedAt)
}

func TestSubjectBoundResetConsumeDoesNotProvisionCredential(t *testing.T) {
	s, record := subjectResetRecord(t)
	require.NoError(t, s.CreatePasswordResetForSubject(t.Context(), record))
	delete(s.passwords, record.SubjectID.String())
	result, err := s.ConsumePasswordReset(t.Context(), goauth.PasswordResetConsumeRequest{
		Selector: record.Selector, Digest: record.Digest, PasswordPHC: "replacement", Now: record.CreatedAt,
	})
	require.NoError(t, err)
	require.Equal(t, goauth.PasswordResetInvalid, result.Status)
	require.Empty(t, s.passwords)
	require.Nil(t, s.resets[record.Selector].ConsumedAt)
}

func TestSubjectResetPreparationRequiresCurrentAuthenticatedToken(t *testing.T) {
	for _, scenario := range []string{"bad digest", "used", "expired", "inactive", "credential-less"} {
		t.Run(scenario, func(t *testing.T) {
			s, record := subjectResetRecord(t)
			require.NoError(t, s.CreatePasswordResetForSubject(t.Context(), record))
			request := goauth.PasswordResetConsumeRequest{Selector: record.Selector, Digest: record.Digest, Now: record.CreatedAt}
			switch scenario {
			case "bad digest":
				request.Digest = goauth.SecretDigest{KeyID: "wrong", Digest: make([]byte, 32)}
			case "used":
				value := record.CreatedAt
				s.resets[record.Selector].ConsumedAt = &value
			case "expired":
				request.Now = record.ExpiresAt
			case "inactive":
				account := s.accounts[record.SubjectID.String()]
				account.Subject.Status = goauth.SubjectStatusDisabled
				s.accounts[record.SubjectID.String()] = account
			case "credential-less":
				delete(s.passwords, record.SubjectID.String())
			}
			called := false
			result, err := s.ConsumePasswordResetWithPreparation(t.Context(), request,
				func(context.Context, goauth.Account) (string, error) { called = true; return preparedResetPHC, nil })
			require.NoError(t, err)
			require.NotEqual(t, goauth.PasswordResetConsumed, result.Status)
			require.False(t, called)
		})
	}
}

func TestSubjectResetPreparationRechecksConfiguredExpiry(t *testing.T) {
	s, record := subjectResetRecord(t)
	require.NoError(t, s.CreatePasswordResetForSubject(t.Context(), record))
	now := record.CreatedAt
	ctx := authclock.With(t.Context(), func() time.Time { return now })
	result, err := s.ConsumePasswordResetWithPreparation(ctx, goauth.PasswordResetConsumeRequest{
		Selector: record.Selector, Digest: record.Digest, Now: now,
	}, func(ctx context.Context, account goauth.Account) (string, error) {
		// A host read must be able to join the isolated transaction without deadlock.
		_, err := s.GetLocalAccount(ctx, account.Subject.ID)
		require.NoError(t, err)
		now = record.ExpiresAt
		return preparedResetPHC, nil
	})
	require.NoError(t, err)
	require.Equal(t, goauth.PasswordResetExpired, result.Status)
	require.Equal(t, "existing-password-phc", s.passwords[record.SubjectID.String()])
	require.Nil(t, s.resets[record.Selector].ConsumedAt)
}

func TestSubjectResetPreparationFailuresRollBack(t *testing.T) {
	for _, scenario := range []string{"hash error", resetPreparationCancel, "empty phc"} {
		t.Run(scenario, func(t *testing.T) {
			s, record := subjectResetRecord(t)
			require.NoError(t, s.CreatePasswordResetForSubject(t.Context(), record))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			hashErr := errors.New("hash failed")
			_, err := s.ConsumePasswordResetWithPreparation(ctx, goauth.PasswordResetConsumeRequest{
				Selector: record.Selector, Digest: record.Digest, Now: record.CreatedAt,
			}, func(context.Context, goauth.Account) (string, error) {
				switch scenario {
				case "hash error":
					return "", hashErr
				case resetPreparationCancel:
					cancel()
					return preparedResetPHC, nil
				default:
					return "", nil
				}
			})
			switch scenario {
			case "hash error":
				require.ErrorIs(t, err, hashErr)
			case resetPreparationCancel:
				require.ErrorIs(t, err, context.Canceled)
			default:
				require.ErrorIs(t, err, goauth.ErrInvalidPassword)
			}
			require.Equal(t, "existing-password-phc", s.passwords[record.SubjectID.String()])
			require.Nil(t, s.resets[record.Selector].ConsumedAt)
		})
	}
}

func TestSubjectResetCreationRejectsForeignStoreTransaction(t *testing.T) {
	s, record := subjectResetRecord(t)
	foreign := NewStore()
	err := foreign.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		return s.CreatePasswordResetForSubject(ctx, record)
	})
	require.ErrorIs(t, err, errForeignStoreTransaction)
	require.Empty(t, s.resets)
	require.Empty(t, foreign.resets)
}
