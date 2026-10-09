package externalconsumerprobe

//nolint:gosec // G101: Generated consumer contains only synthetic dictionary and password fixtures.
const localCommonPasswordProbeTest = `
func TestLocalCommonPasswordCheckerExternalConsumer(t *testing.T) {
	words := []string{"Tenant-Example-Passphrase"}
	var option goauth.LocalCommonPasswordCheckerOption = goauth.WithBuiltInCommonPasswords()
	checker, err := goauth.NewLocalCommonPasswordChecker(words, option)
	if err != nil {
		t.Fatal(err)
	}
	words[0] = "Changed-Example-Passphrase"
	policy := goauth.PasswordPolicy{Blocklist: checker}
	for _, value := range []string{" tenant-EXAMPLE-passphrase ", "password"} {
		if !errors.Is(policy.Validate(value), goauth.ErrCommonPassword) {
			t.Fatal("local and built-in dictionaries must both apply")
		}
	}
	if err := policy.Validate("Changed-Example-Passphrase"); err != nil {
		t.Fatal("the checker retained the caller's slice")
	}
	if err := goauth.DefaultPasswordPolicy().Validate("Tenant-Example-Passphrase"); err != nil {
		t.Fatal("local construction changed the default dictionary")
	}
	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.PasswordPolicy = policy
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = fixture.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "local-dictionary-probe@example.test", Password: "Tenant-Example-Passphrase",
	})
	if !errors.Is(err, goauth.ErrCommonPassword) {
		t.Fatal("Runtime did not use the injected local checker")
	}
}
`
