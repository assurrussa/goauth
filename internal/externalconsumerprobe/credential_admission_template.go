package externalconsumerprobe

//nolint:gosec // Isolated generated test fixture, never real credentials.
const credentialAdmissionProbeTest = `
func TestCredentialAdmissionExternalConsumer(t *testing.T) {
	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.LoginRateLimit = goauth.RateLimitPolicy{Window: time.Minute, Limit: 1}
		config.CredentialVerificationRateLimit = goauth.RateLimitPolicy{Window: time.Minute, Limit: 2}
	})
	if err != nil {
		t.Fatal(err)
	}
	const password = "Probe-Credential-Admission-Passphrase-42"
	_, err = fixture.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "admission-probe@example.test", Password: password,
	})
	if err != nil {
		t.Fatal(err)
	}
	credential := goauth.Credential{
		Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: "admission-probe@example.test"},
		Password: password,
	}
	for range 2 {
		if _, err := fixture.Runtime.VerifyCredential(t.Context(), credential); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fixture.Runtime.VerifyCredential(t.Context(), credential); !errors.Is(err, goauth.ErrAuthenticationRateLimited) {
		t.Fatalf("credential limit not enforced: %v", err)
	}
	if _, err := fixture.Runtime.Login(t.Context(), goauth.LoginRequest{Credential: credential}); err != nil {
		t.Fatal(err)
	}
	_, err = fixture.Runtime.Login(t.Context(), goauth.LoginRequest{Credential: credential})
	if !errors.Is(err, goauth.ErrAuthenticationRateLimited) {
		t.Fatalf("independent login limit not enforced: %v", err)
	}
}
`
