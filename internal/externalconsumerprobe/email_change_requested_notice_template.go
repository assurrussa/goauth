package externalconsumerprobe

const emailChangeRequestedNoticeProbeTest = `
func TestPreviousEmailNoticeExternalConsumer(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.ManagedNotificationDelivery = true
		config.Now = func() time.Time { return now }
	})
	if err != nil {
		t.Fatal(err)
	}
	account, err := fixture.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "notice.previous@example.test", Password: "Probe-Notice-Passphrase-123",
	})
	if err != nil {
		t.Fatal(err)
	}
	before := len(fixture.Events.Events())
	err = fixture.Runtime.RequestEmailChangeWithPreviousEmailNotice(
		t.Context(), account.Subject.ID, "notice.next@example.test", "notice.other@example.test",
	)
	if !errors.Is(err, goauth.ErrSecurityVersionMismatch) || len(fixture.Events.Events()) != before {
		t.Fatal("mismatched previous recipient did not reject before issuance")
	}
	if err := fixture.Runtime.RequestEmailChangeWithPreviousEmailNotice(
		t.Context(), account.Subject.ID, "notice.next@example.test", account.PrimaryEmail.NormalizedValue,
	); err != nil {
		t.Fatal(err)
	}
	events := fixture.Events.Events()
	if len(events) != before+2 {
		t.Fatal("issuance did not enqueue exactly the code and previous-mailbox notice")
	}
	var challenge, notice goauth.EncryptedEvent
	for _, event := range events[before:] {
		switch event.Type {
		case "email_change":
			challenge = event
		case "email_change_requested":
			notice = event
		default:
			t.Fatal("issuance enqueued an unexpected event type")
		}
	}
	if challenge.ID == "" || notice.ID == "" || challenge.ID == notice.ID ||
		notice.ReferenceID == "" || notice.ReferenceID != challenge.ReferenceID ||
		!notice.ValidUntil.After(challenge.ValidUntil) {
		t.Fatal("requested notice lost distinct delivery identity, issuance binding or historical deadline")
	}
	codeMail, err := fixture.Runtime.DecryptNotificationEvent(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if codeMail.Template != "email_change" || codeMail.To != "notice.next@example.test" ||
		len(codeMail.Data["code"]) != 6 {
		t.Fatal("confirmation code was not restricted to the new mailbox")
	}
	oldMail, err := fixture.Runtime.DecryptNotificationEvent(notice)
	if err != nil {
		t.Fatal(err)
	}
	if oldMail.Template != "email_change_requested" ||
		oldMail.To != account.PrimaryEmail.NormalizedValue || len(oldMail.Data) != 0 {
		t.Fatal("previous mailbox notice contains unexpected recipient, template or credential data")
	}
	err = fixture.Runtime.RequestEmailChangeWithPreviousEmailNotice(
		t.Context(), account.Subject.ID, "notice.next@example.test", account.PrimaryEmail.NormalizedValue,
	)
	if !errors.Is(err, goauth.ErrConfirmationResendDelay) || len(fixture.Events.Events()) != len(events) {
		t.Fatal("rate-limited retry emitted a duplicate requested notice")
	}
}
`
