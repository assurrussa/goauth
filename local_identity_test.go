package goauth_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

//nolint:gosec // Synthetic test credentials, never used outside fixtures.
const (
	localIdentityLegacyPassword   = "Legacy-Passphrase-42"
	localIdentityMigratedPassword = "Migrated-Strict-Passphrase-42"
	localIdentityStrictPassword   = "Strict-Passphrase-42"
)

const localIdentityScheme goauth.IdentifierScheme = "hub_login"

func localIdentityFixture(t *testing.T, options ...testkit.RuntimeOption) *testkit.Fixture {
	t.Helper()
	options = append([]testkit.RuntimeOption{func(c *goauth.Config) {
		c.IdentifierResolvers = map[goauth.IdentifierScheme]goauth.IdentifierResolver{
			localIdentityScheme: goauth.IdentifierResolverFunc(func(
				_ context.Context, input goauth.IdentifierInput,
			) (goauth.IdentifierInput, error) {
				return input, nil
			}),
		}
	}}, options...)
	f, err := testkit.NewRuntime(options...)
	require.NoError(t, err)
	return f
}

func legacyIdentityPHC(password string) string {
	salt := bytes.Repeat([]byte{42}, 16)
	digest := argon2.IDKey([]byte(password), salt, 3, 65536, 1, 32)
	return "$argon2id$v=19$m=65536,t=3,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(digest)
}

func localIdentityImport(password string) goauth.ImportLocalIdentityRequest {
	return goauth.ImportLocalIdentityRequest{
		SubjectID:   goauth.NewSubjectID(),
		Identifier:  goauth.IdentifierInput{Scheme: localIdentityScheme, Value: "LegacyLogin"},
		PasswordPHC: legacyIdentityPHC(password), PasswordInputPolicy: goauth.PasswordInputPolicyLegacyBytes256,
		Status: goauth.SubjectStatusActive,
	}
}

func TestLocalIdentityProvisionPreservesRealmAndEmailBoundaries(t *testing.T) {
	f := localIdentityFixture(t)
	const password = "Local-Identity-Passphrase-42"
	input := goauth.IdentifierInput{Scheme: localIdentityScheme, Value: "Operator"}
	account, err := f.Runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
		Identifier: input,
		Password:   password,
	})
	require.NoError(t, err)
	require.Zero(t, account.PrimaryEmail)
	require.False(t, account.EmailVerified())
	found, err := f.Runtime.FindAccount(t.Context(), input)
	require.NoError(t, err)
	require.Equal(t, account.Subject.ID, found.Subject.ID)
	verified, err := f.Runtime.VerifyCredential(t.Context(), goauth.Credential{
		Identifier: input,
		Password:   password,
	})
	require.NoError(t, err)
	require.Equal(t, account.Subject.ID, verified.Subject.ID)
	result, err := f.Runtime.Login(t.Context(), goauth.LoginRequest{
		Credential: goauth.Credential{
			Identifier: input,
			Password:   password,
		},
	})
	require.NoError(t, err)
	require.Equal(t, goauth.SessionScopeConfirmation, result.Tokens.Session.Scope)
	_, err = f.Runtime.Login(t.Context(), goauth.LoginRequest{
		Realm: goauth.RealmAdmin,
		Credential: goauth.Credential{
			Identifier: input,
			Password:   password,
		},
	})
	require.ErrorIs(t, err, goauth.ErrEmailVerificationRequired)
	require.ErrorIs(t,
		f.Runtime.SendEmailChallenge(t.Context(), account.Subject.ID, goauth.EmailChallengePurposeVerification),
		goauth.ErrInvalidIdentifier)
	require.ErrorIs(t,
		f.Runtime.RequestEmailChange(t.Context(), account.Subject.ID, "new@example.test"), goauth.ErrInvalidIdentifier)
	require.NoError(t, f.Runtime.RequestPasswordReset(t.Context(), "Operator"))
	require.Empty(t, f.Events.Events())
	_, err = f.Runtime.ChangePassword(t.Context(), goauth.ChangePasswordRequest{
		SubjectID:       account.Subject.ID,
		CurrentPassword: password,
		NewPassword:     "Updated-Identity-Passphrase-43",
	})
	require.NoError(t, err, "email-less password changes retain audit without an empty email notification")
	require.Empty(t, f.Events.Events())
	_, err = f.Runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
		Identifier: input,
		Password:   password,
	})
	require.ErrorIs(t, err, goauth.ErrIdentifierAlreadyExists)
	input.Value = "operator"
	other, err := f.Runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
		Identifier: input,
		Password:   password,
	})
	require.NoError(t, err, "custom resolver output must not be silently case folded")
	require.NotEqual(t, account.Subject.ID, other.Subject.ID)
}

func TestLocalIdentityLegacyCredentialCompatibility(t *testing.T) {
	for _, test := range []struct{ name, password string }{
		{"129 code points", strings.Repeat("x", 129)},
		{"binary bytes", string([]byte{'p', 0xff, 0, 'a'})},
		{"256 bytes", strings.Repeat("z", 256)},
	} {
		t.Run(test.name, func(t *testing.T) {
			password := test.password
			f := localIdentityFixture(t)
			request := localIdentityImport(password)
			account, err := f.Runtime.ImportLocalIdentity(t.Context(), request)
			require.NoError(t, err)
			require.Equal(t, request.SubjectID, account.Subject.ID)
			require.Zero(t, account.PrimaryEmail)
			credential := goauth.Credential{
				Identifier: request.Identifier,
				Password:   password,
			}
			verified, err := f.Runtime.VerifyCredential(t.Context(), credential)
			require.NoError(t, err)
			require.Equal(t, account.Subject.ID, verified.Subject.ID)
			credential.Password += "mismatch"
			_, err = f.Runtime.VerifyCredential(t.Context(), credential)
			require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
			credential.Password = strings.Repeat("x", 257)
			_, err = f.Runtime.VerifyCredential(t.Context(), credential)
			require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
			_, err = f.Runtime.ChangePassword(t.Context(), goauth.ChangePasswordRequest{
				SubjectID:       account.Subject.ID,
				CurrentPassword: password,
				NewPassword:     localIdentityMigratedPassword,
			})
			require.NoError(t, err)
			record, err := f.Store.GetLocalAccount(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			require.Equal(t, goauth.PasswordInputPolicyUnicode, record.PasswordInputPolicy)
			require.EqualValues(t, 2, record.Account.Subject.SecurityVersion)
			credential.Password = password
			_, err = f.Runtime.VerifyCredential(t.Context(), credential)
			require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
			credential.Password = localIdentityMigratedPassword
			_, err = f.Runtime.VerifyCredential(t.Context(), credential)
			require.NoError(t, err)
		})
	}
}

func TestLocalIdentityImportRejectsConflictsAndPreservesDisabled(t *testing.T) {
	f := localIdentityFixture(t)
	request := localIdentityImport(localIdentityLegacyPassword)
	request.Status = goauth.SubjectStatusDisabled
	account, err := f.Runtime.ImportLocalIdentity(t.Context(), request)
	require.NoError(t, err)
	require.Equal(t, request.Status, account.Subject.Status)
	_, err = f.Runtime.VerifyCredential(t.Context(), goauth.Credential{
		Identifier: request.Identifier,
		Password:   localIdentityLegacyPassword,
	})
	require.ErrorIs(t, err, goauth.ErrAccountUnavailable)
	_, err = f.Runtime.ImportLocalIdentity(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrIdentifierAlreadyExists)
	request.SubjectID = goauth.NewSubjectID()
	_, err = f.Runtime.ImportLocalIdentity(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrIdentifierAlreadyExists)
	request.SubjectID = account.Subject.ID
	request.Identifier.Value = "different"
	_, err = f.Runtime.ImportLocalIdentity(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrIdentifierAlreadyExists)
}

func TestLocalIdentityImportRejectsNonstandardLegacyProfiles(t *testing.T) {
	f := localIdentityFixture(t)
	request := localIdentityImport(localIdentityLegacyPassword)
	for _, phc := range []string{
		strings.Replace(request.PasswordPHC, "m=65536", "m=19456", 1),
		strings.Replace(request.PasswordPHC, "t=3", "t=2", 1),
		strings.Replace(request.PasswordPHC, "p=1", "p=2", 1),
		strings.Replace(request.PasswordPHC, "v=19", "v=16", 1),
		strings.Replace(request.PasswordPHC, "m=65536,t=3,p=1", "t=3,m=65536,p=1", 1),
		strings.Replace(request.PasswordPHC, "m=65536", "m=065536", 1),
		"$argon2id$unknown", "opaque hash",
		"$argon2id$v=19$m=65536,t=3,p=1$" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)) + "$" +
			base64.RawStdEncoding.EncodeToString(make([]byte, 32)),
		"$argon2id$v=19$m=65536,t=3,p=1$" + base64.RawStdEncoding.EncodeToString(make([]byte, 16)) + "$" +
			base64.RawStdEncoding.EncodeToString(make([]byte, 64)),
	} {
		rejected := request
		rejected.PasswordPHC = phc
		account, err := f.Runtime.ImportLocalIdentity(t.Context(), rejected)
		require.ErrorIs(t, err, goauth.ErrInvalidPassword)
		require.Zero(t, account)
	}
	request.PasswordInputPolicy = "unknown"
	_, err := f.Runtime.ImportLocalIdentity(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrInvalidPassword)
}

type (
	localIdentityLegacyStore  struct{ goauth.RuntimeStore }
	localIdentityCustomHasher struct{ goauth.PasswordHasher }
)

func TestLocalIdentityUnsupportedCapabilitiesFailClosed(t *testing.T) {
	f := localIdentityFixture(t, func(c *goauth.Config) { c.Store = localIdentityLegacyStore{RuntimeStore: c.Store} })
	_, err := f.Runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
		Identifier: goauth.IdentifierInput{Scheme: localIdentityScheme, Value: "unsupported"},
		Password:   "Unsupported-Passphrase-42",
	})
	require.ErrorIs(t, err, goauth.ErrLocalIdentityUnsupported)
	request := localIdentityImport(localIdentityLegacyPassword)
	_, err = f.Runtime.ImportLocalIdentity(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrLocalIdentityUnsupported)
	h, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{})
	require.NoError(t, err)
	f = localIdentityFixture(t, func(c *goauth.Config) { c.PasswordHasher = localIdentityCustomHasher{PasswordHasher: h} })
	_, err = f.Runtime.ImportLocalIdentity(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrLocalIdentityUnsupported)
}

func TestLocalIdentityPrivilegedWritesRollBackOnAuditFailure(t *testing.T) {
	denied := errors.New("audit unavailable")
	f := localIdentityFixture(t, func(c *goauth.Config) {
		c.AuditSink = goauth.AuditSinkFunc(func(context.Context, goauth.SecurityEvent) error { return denied })
	})
	request := localIdentityImport(localIdentityLegacyPassword)
	account, err := f.Runtime.ImportLocalIdentity(t.Context(), request)
	require.ErrorIs(t, err, denied)
	require.Zero(t, account)
	_, err = f.Runtime.GetAccount(t.Context(), request.SubjectID)
	require.ErrorIs(t, err, goauth.ErrAccountNotFound)
	_, err = f.Runtime.FindAccount(t.Context(), request.Identifier)
	require.ErrorIs(t, err, goauth.ErrAccountNotFound)
}

func TestLocalIdentityNewPasswordPolicyRemainsStrict(t *testing.T) {
	f := localIdentityFixture(t)
	input := goauth.IdentifierInput{Scheme: localIdentityScheme, Value: "strict"}
	for _, password := range []string{strings.Repeat("x", 129), string([]byte{0xff}), "tiny"} {
		_, err := f.Runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
			Identifier: input,
			Password:   password,
		})
		require.ErrorIs(t, err, goauth.ErrInvalidPassword)
	}
	input.Scheme = goauth.IdentifierSchemeEmail
	_, err := f.Runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
		Identifier: input,
		Password:   localIdentityStrictPassword,
	})
	require.ErrorIs(t, err, goauth.ErrInvalidIdentifierScheme)
}

func TestLocalIdentityPersistedLegacyPolicyRejectsCustomVerifier(t *testing.T) {
	f := localIdentityFixture(t)
	request := localIdentityImport(localIdentityLegacyPassword)
	_, err := f.Runtime.ImportLocalIdentity(t.Context(), request)
	require.NoError(t, err)
	hasher, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{})
	require.NoError(t, err)
	custom := localIdentityFixture(t, func(c *goauth.Config) {
		c.Store = f.Store
		c.AuthTransaction = f.Store
		c.AuditSink = f.Store
		c.PasswordHasher = localIdentityCustomHasher{PasswordHasher: hasher}
	})
	_, err = custom.Runtime.VerifyCredential(t.Context(), goauth.Credential{
		Identifier: request.Identifier,
		Password:   localIdentityLegacyPassword,
	})
	require.ErrorIs(t, err, goauth.ErrPasswordVerificationUnavailable)
}

type localIdentityUnknownTransaction struct{ base goauth.AuthTransaction }

func (tx localIdentityUnknownTransaction) InAuthTransaction(ctx context.Context, fn func(context.Context) error) error {
	if err := tx.base.InAuthTransaction(ctx, fn); err != nil {
		return err
	}
	return goauth.ErrOperationOutcomeUnknown
}

func TestLocalIdentityUnknownCommitReturnsNoSuccessfulAccount(t *testing.T) {
	f := localIdentityFixture(t, func(c *goauth.Config) {
		c.AuthTransaction = localIdentityUnknownTransaction{base: c.AuthTransaction}
	})
	request := localIdentityImport(localIdentityLegacyPassword)
	account, err := f.Runtime.ImportLocalIdentity(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrOperationOutcomeUnknown)
	require.Zero(t, account)
	// A server commit can precede a lost acknowledgment; callers must reconcile
	// their durable mapping rather than assume an unknown outcome rolled back.
	stored, err := f.Runtime.GetAccount(t.Context(), request.SubjectID)
	require.NoError(t, err)
	require.Equal(t, request.SubjectID, stored.Subject.ID)
}

func TestLocalIdentityUnicodeImportDoesNotBroadenVerification(t *testing.T) {
	password := strings.Repeat("q", 129)
	for _, policy := range []goauth.PasswordInputPolicy{"", goauth.PasswordInputPolicyUnicode} {
		f := localIdentityFixture(t)
		request := localIdentityImport(password)
		request.PasswordInputPolicy = policy
		_, err := f.Runtime.ImportLocalIdentity(t.Context(), request)
		require.NoError(t, err)
		_, err = f.Runtime.VerifyCredential(t.Context(), goauth.Credential{Identifier: request.Identifier, Password: password})
		require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
	}
}

func TestLocalIdentityImportValidatesCanonicalInputs(t *testing.T) {
	f := localIdentityFixture(t)
	request := localIdentityImport(localIdentityLegacyPassword)
	for _, value := range []string{"", " ", strings.Repeat("x", 257), "invalid\x00login", string([]byte{0xff})} {
		invalid := request
		invalid.Identifier.Value = value
		_, err := f.Runtime.ImportLocalIdentity(t.Context(), invalid)
		require.ErrorIs(t, err, goauth.ErrInvalidIdentifier)
	}
	invalid := request
	invalid.SubjectID = goauth.NilSubjectID
	_, err := f.Runtime.ImportLocalIdentity(t.Context(), invalid)
	require.ErrorIs(t, err, goauth.ErrInvalidSubjectID)
	invalid = request
	invalid.Status = ""
	_, err = f.Runtime.ImportLocalIdentity(t.Context(), invalid)
	require.ErrorIs(t, err, goauth.ErrInvalidSubjectStatus)
	invalid = request
	invalid.Identifier.Scheme = "unregistered"
	_, err = f.Runtime.ImportLocalIdentity(t.Context(), invalid)
	require.ErrorIs(t, err, goauth.ErrInvalidIdentifierScheme)
}

type localIdentityCustomLookupStore struct {
	goauth.RuntimeStore
	expected goauth.IdentifierInput
	record   goauth.LocalAccountRecord
}

func (s localIdentityCustomLookupStore) FindAccount(_ context.Context, input goauth.IdentifierInput) (goauth.Account, error) {
	if input != s.expected {
		return goauth.Account{}, goauth.ErrAccountNotFound
	}
	return s.record.Account, nil
}

func (s localIdentityCustomLookupStore) FindLocalAccount(
	_ context.Context, input goauth.IdentifierInput,
) (goauth.LocalAccountRecord, error) {
	if input != s.expected {
		return goauth.LocalAccountRecord{}, goauth.ErrAccountNotFound
	}
	return s.record, nil
}

func TestExistingRootCustomStoreRetainsItsIdentifierContract(t *testing.T) {
	hasher, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{})
	require.NoError(t, err)
	phc, err := hasher.HashPassword(localIdentityStrictPassword)
	require.NoError(t, err)
	record := goauth.LocalAccountRecord{
		Account: goauth.Account{Subject: goauth.Subject{
			ID: goauth.NewSubjectID(), Status: goauth.SubjectStatusActive, SecurityVersion: 1,
		}},
		PasswordPHC: phc,
	}
	for _, value := range []string{strings.Repeat("x", 257), "custom\x00value", string([]byte{'p', 0xff})} {
		expected := goauth.IdentifierInput{Scheme: localIdentityScheme, Value: value}
		f := localIdentityFixture(t, func(c *goauth.Config) {
			c.Store = localIdentityCustomLookupStore{RuntimeStore: c.Store, expected: expected, record: record}
		})
		found, err := f.Runtime.FindAccount(t.Context(), expected)
		require.NoError(t, err)
		require.Equal(t, record.Account.Subject.ID, found.Subject.ID)
		verified, err := f.Runtime.VerifyCredential(t.Context(), goauth.Credential{
			Identifier: expected, Password: localIdentityStrictPassword,
		})
		require.NoError(t, err)
		require.Equal(t, record.Account.Subject.ID, verified.Subject.ID)
	}
}
