package externalconsumerprobe

const passwordResetRecipientProbeTest = `
type probeResetRecipient struct { subject goauth.SubjectID }
func (p *probeResetRecipient) LookupPasswordResetSubject(context.Context, string) (goauth.SubjectID, error) {
 return p.subject, nil
}
func (p *probeResetRecipient) ResolvePasswordResetRecipient(_ context.Context, account goauth.Account, requested string) (string, error) {
 if account.Subject.ID != p.subject || (requested != "" && requested != "recovery-probe@example.test") {
  return "", goauth.ErrAccountNotFound
 }
 return "recovery-probe@example.test", nil
}
func (p *probeResetRecipient) PreparePasswordResetPassword(context.Context, goauth.Account, string) (string, error) { return "", nil }
func TestPasswordResetRecipientExternalConsumer(t *testing.T) {
 policy := &probeResetRecipient{}
 fixture, err := testkit.NewRuntime(func(c *goauth.Config) { c.PasswordResetRecipientResolver = policy })
 if err != nil { t.Fatal(err) }
 account, err := fixture.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
  Email: "primary-recovery-probe@example.test", Password: "Recovery-Probe-Passphrase-42",
 })
 if err != nil { t.Fatal(err) }
 policy.subject = account.Subject.ID
 var capability goauth.PasswordResetSubjectStore = fixture.Store
 _ = capability
 var invalidate func(*postgres.Runtime, context.Context, goauth.SubjectID) error = (*postgres.Runtime).InvalidatePasswordResets
 if err := invalidate(nil, t.Context(), account.Subject.ID); err == nil { t.Fatal("uninitialized invalidation accepted") }
 var receipt goauth.PasswordResetReceipt
 if err := fixture.Runtime.RequestPasswordResetWithReceipt(t.Context(), "recovery-probe@example.test",
  func(_ context.Context, r goauth.PasswordResetReceipt) error { receipt = r; return nil }); err != nil { t.Fatal(err) }
 if receipt.SubjectID != account.Subject.ID || receipt.Selector == "" { t.Fatal("incorrect subject-bound receipt") }
 events := fixture.Events.Events()
 if len(events) != 1 { t.Fatalf("events = %d", len(events)) }
 notification, err := fixture.Runtime.DecryptNotificationEvent(events[0])
 if err != nil || notification.To != "recovery-probe@example.test" { t.Fatalf("recipient = %q, %v", notification.To, err) }
 if err := fixture.Store.InvalidatePasswordResets(t.Context(), account.Subject.ID, time.Now().UTC()); err != nil { t.Fatal(err) }
}
`
