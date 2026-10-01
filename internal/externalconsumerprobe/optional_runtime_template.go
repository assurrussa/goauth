package externalconsumerprobe

const disabledDeliveryProbeTest = `
func TestDisabledDeliveryRuntimeExternalConsumer(t *testing.T) {
	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.NotificationDelivery = goauth.NotificationDeliveryDisabled
		config.EventSink = nil
		config.URLBuilder = nil
		config.OutboxAEADKeys = goauth.KeyRing{}
	})
	if err != nil {
		t.Fatal(err)
	}
	account, err := fixture.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "disabled-probe@example.test", Password: "Probe-Disabled-Passphrase-123",
	})
	if err != nil {
		t.Fatal(err)
	}
	before, err := fixture.Runtime.GetAccount(t.Context(), account.Subject.ID)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	commands := []func() error{
		func() error {
			return fixture.Runtime.RequestPasswordReset(t.Context(), account.PrimaryEmail.DisplayValue)
		},
		func() error {
			return fixture.Runtime.RequestPasswordResetWithReceipt(t.Context(), account.PrimaryEmail.DisplayValue,
				func(context.Context, goauth.PasswordResetReceipt) error { called = true; return nil })
		},
		func() error {
			return fixture.Runtime.ResetPassword(t.Context(), "old-token", "Probe-Replacement-Passphrase-456")
		},
		func() error {
			return fixture.Runtime.SendEmailChallenge(
				t.Context(), account.Subject.ID, goauth.EmailChallengePurposeVerification,
			)
		},
		func() error {
			return fixture.Runtime.RequestEmailChangeWithPassword(t.Context(), goauth.PasswordEmailChangeRequest{
				SubjectID: account.Subject.ID, CurrentPassword: "incorrect-disabled-password",
				NewEmail: "changed-probe@example.test",
			})
		},
	}
	// Disabled commands must not admit password guesses or consume their rate budget.
	for range 12 {
		for index, command := range commands {
			if err := command(); !errors.Is(err, goauth.ErrNotificationDeliveryDisabled) {
				t.Fatalf("disabled command %d: %v", index, err)
			}
		}
	}
	after, err := fixture.Runtime.GetAccount(t.Context(), account.Subject.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Subject.SecurityVersion != before.Subject.SecurityVersion ||
		after.PrimaryEmail.NormalizedValue != before.PrimaryEmail.NormalizedValue || called || len(fixture.Events.Events()) != 0 {
		t.Fatal("disabled email commands mutated account, enqueued delivery or invoked receipt")
	}
	changed, err := fixture.Runtime.ChangePassword(t.Context(), goauth.ChangePasswordRequest{
		SubjectID: account.Subject.ID, CurrentPassword: "Probe-Disabled-Passphrase-123",
		NewPassword: "Probe-Replacement-Passphrase-456",
	})
	if err != nil {
		t.Fatal(err)
	}
	if changed.Subject.SecurityVersion <= before.Subject.SecurityVersion || len(fixture.Events.Events()) != 0 {
		t.Fatal("disabled delivery did not retain password security mutation without enqueue")
	}
	_, err = fixture.Runtime.Login(t.Context(), goauth.LoginRequest{
		Realm: goauth.RealmUser, Credential: goauth.Credential{
			Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: account.PrimaryEmail.DisplayValue},
			Password:   "Probe-Replacement-Passphrase-456",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = testkit.NewRuntime(func(config *goauth.Config) {
		config.NotificationDelivery = goauth.NotificationDeliveryDisabled
		config.EventSink = nil
		config.AuditSink = nil
	})
	if err == nil {
		t.Fatal("disabled delivery accepted missing mandatory transactional audit")
	}
}
`
