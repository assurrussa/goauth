package goauth_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

func TestLocalCommonPasswordCheckerCopiesAndNormalizes(t *testing.T) {
	t.Parallel()

	passwords := []string{" Example-Passphrase ", "EXAMPLE-PASSPHRASE", "\u2003ПАРОЛЬ-ПРИМЕР\u00a0", "Straße", "CAFÉ", "�"}
	checker, err := goauth.NewLocalCommonPasswordChecker(passwords)
	require.NoError(t, err)
	passwords[0] = "Changed-Passphrase"
	passwords[1] = ""
	passwords[2] = "Other-Passphrase"

	for _, value := range []string{"example-passphrase", " EXAMPLE-PASSPHRASE\t", "пароль-пример", "straße", "café", "�"} {
		require.True(t, checker.IsCommonPassword(value))
	}
	for _, value := range []string{"Changed-Passphrase", "Other-Passphrase", "STRASSE", "cafe\u0301", "", "\xff"} {
		require.False(t, checker.IsCommonPassword(value))
	}
}

func TestLocalCommonPasswordCheckerBuiltinOptionIsIsolated(t *testing.T) {
	t.Parallel()

	defaultBefore := goauth.DefaultPasswordPolicy()
	options := []goauth.LocalCommonPasswordCheckerOption{goauth.WithBuiltInCommonPasswords()}
	checker, err := goauth.NewLocalCommonPasswordChecker([]string{"Local-Example-Passphrase"}, options...)
	require.NoError(t, err)
	options[0] = nil

	customOnly, err := goauth.NewLocalCommonPasswordChecker([]string{"Local-Example-Passphrase"})
	require.NoError(t, err)
	defaultAfter := goauth.DefaultPasswordPolicy()
	for _, policy := range []goauth.PasswordPolicy{defaultBefore, defaultAfter} {
		require.Equal(t, 8, policy.MinLength)
		require.Equal(t, 128, policy.MaxLength)
		require.NoError(t, policy.Validate("Local-Example-Passphrase"))
		require.NoError(t, policy.Validate("Abcdefg!"))
		require.ErrorIs(t, policy.Validate("Abcdef!"), goauth.ErrInvalidPassword)
	}
	for _, value := range []string{
		"12345678", "123456789", "1234567890", "abcdefgh",
		"admin123", "iloveyou", "letmein123", "password",
		"password1", "password123", "qwerty123", "welcome1",
	} {
		require.True(t, checker.IsCommonPassword(" "+strings.ToUpper(value)+"\t"))
		require.False(t, customOnly.IsCommonPassword(value))
		require.ErrorIs(t, defaultBefore.Validate(value), goauth.ErrCommonPassword)
		require.ErrorIs(t, defaultAfter.Validate(value), goauth.ErrCommonPassword)
	}
	require.True(t, checker.IsCommonPassword("Local-Example-Passphrase"))
	require.True(t, customOnly.IsCommonPassword("Local-Example-Passphrase"))
	require.False(t, checker.IsCommonPassword("Unlisted-Example-Passphrase"))
}

func TestLocalCommonPasswordCheckerEmptySetAndRepeatedOption(t *testing.T) {
	t.Parallel()

	for _, passwords := range [][]string{nil, {}} {
		empty, err := goauth.NewLocalCommonPasswordChecker(passwords)
		require.NoError(t, err)
		require.NotNil(t, empty)
		require.False(t, empty.IsCommonPassword("password"))
		require.False(t, empty.IsCommonPassword(""))
		policy := goauth.PasswordPolicy{Blocklist: empty}
		require.NoError(t, policy.Validate("password"))
		require.ErrorIs(t, policy.Validate("short"), goauth.ErrInvalidPassword)

		builtins, err := goauth.NewLocalCommonPasswordChecker(
			passwords, goauth.WithBuiltInCommonPasswords(), goauth.WithBuiltInCommonPasswords(),
		)
		require.NoError(t, err)
		require.True(t, builtins.IsCommonPassword("password"))
	}
}

func TestLocalCommonPasswordCheckerRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		passwords []string
		options   []goauth.LocalCommonPasswordCheckerOption
		want      string
	}{
		{"empty entry", []string{""}, nil, "entry 0 is empty after trimming"},
		{"blank entry", []string{"valid", "\u2003\t\u00a0"}, nil, "entry 1 is empty after trimming"},
		{"invalid UTF-8", []string{"do-not-echo-this\xff"}, nil, "entry 0 is not valid UTF-8"},
		{"nil option", nil, []goauth.LocalCommonPasswordCheckerOption{nil}, "option 0 is nil"},
		{
			"later nil option", nil,
			[]goauth.LocalCommonPasswordCheckerOption{goauth.WithBuiltInCommonPasswords(), nil},
			"option 1 is nil",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			checker, err := goauth.NewLocalCommonPasswordChecker(test.passwords, test.options...)
			require.Nil(t, checker)
			require.EqualError(t, err, "local common password checker: "+test.want)
			require.NotContains(t, err.Error(), "do-not-echo-this")
		})
	}
}

func TestLocalCommonPasswordCheckerConcurrentReads(t *testing.T) {
	t.Parallel()

	passwords := []string{"Concurrent-Example-Passphrase"}
	checker, err := goauth.NewLocalCommonPasswordChecker(passwords, goauth.WithBuiltInCommonPasswords())
	require.NoError(t, err)
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 100 {
				if !checker.IsCommonPassword(" concurrent-EXAMPLE-passphrase ") ||
					!checker.IsCommonPassword("PASSWORD") || checker.IsCommonPassword("Unlisted-Example-Passphrase") {
					t.Error("concurrent lookup changed the immutable dictionary")
					return
				}
			}
		}()
	}
	// The constructor does not retain the caller's slice, even while readers run.
	for range 100 {
		passwords[0] = "Changed-Example-Passphrase"
	}
	wait.Wait()
}

func TestLocalCommonPasswordCheckerIsIssuancePolicyOnly(t *testing.T) {
	t.Parallel()

	var config goauth.Config
	fixture, err := testkit.NewRuntime(func(value *goauth.Config) { config = *value })
	require.NoError(t, err)
	const password = "Existing-Example-Passphrase"
	account, err := fixture.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "local-checker-existing@example.test", Password: password,
	})
	require.NoError(t, err)

	checker, err := goauth.NewLocalCommonPasswordChecker([]string{password}, goauth.WithBuiltInCommonPasswords())
	require.NoError(t, err)
	config.PasswordPolicy = goauth.PasswordPolicy{Blocklist: checker}
	runtime, err := goauth.NewRuntime(config)
	require.NoError(t, err)
	login, err := runtime.Login(t.Context(), loginRequest("local-checker-existing@example.test", password, goauth.RealmUser))
	require.NoError(t, err)
	require.Equal(t, account.Subject.ID, login.Account.Subject.ID)

	_, err = runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "local-checker-new@example.test", Password: password,
	})
	require.ErrorIs(t, err, goauth.ErrCommonPassword)
	require.ErrorIs(t, config.PasswordPolicy.Validate("short"), goauth.ErrInvalidPassword)
	require.ErrorIs(t, config.PasswordPolicy.Validate(strings.Repeat("x", 129)), goauth.ErrInvalidPassword)
	require.ErrorIs(t, config.PasswordPolicy.Validate("invalid\xff"), goauth.ErrInvalidPassword)
	config.PasswordPolicy.DisableBlocklist = true
	require.NoError(t, config.PasswordPolicy.Validate(password))
}
