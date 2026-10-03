package externalconsumerprobe

//nolint:gosec // Generated consumer exercises synthetic fixture passwords only.
const trustedLocalPasswordProbeTest = `
func TestTrustedLocalPasswordExternalConsumer(t *testing.T) {
 fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
  config.NotificationDelivery = goauth.NotificationDeliveryDisabled
  config.EventSink = nil
  config.URLBuilder = nil
  config.OutboxAEADKeys = goauth.KeyRing{}
 })
 if err != nil { t.Fatal(err) }
 var capability goauth.TrustedLocalPasswordStore = fixture.Store
 _ = capability
 account, err := fixture.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
  Email: "trusted-set-probe@example.test", Password: "Trusted-Set-Probe-Passphrase-42",
 })
 if err != nil { t.Fatal(err) }
 disabled, err := fixture.Runtime.SetSubjectStatus(t.Context(), account.Subject.ID, goauth.SubjectStatusDisabled)
 if err != nil { t.Fatal(err) }
 updated, err := fixture.Runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
  SubjectID: account.Subject.ID, NewPassword: "Trusted-Set-Probe-Passphrase-42",
 })
 if err != nil { t.Fatal(err) }
 if updated.Subject.Status != goauth.SubjectStatusDisabled || updated.Subject.SecurityVersion != disabled.SecurityVersion+1 {
  t.Fatal("trusted password set changed status or failed to advance security version")
 }
 if len(fixture.Events.Events()) != 0 { t.Fatal("disabled delivery enqueued a notification") }
}
`

//nolint:gosec // Generated consumer exercises synthetic fixture passwords only.
const trustedLocalPasswordPostgresProbeTest = `
func TestTrustedLocalPasswordManagedExternalConsumer(t *testing.T) {
 runtime := newHostProbeRuntime(t, true)
 projection := hostProbeProjection(t, runtime.Database())
 account, err := runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
  Identifier: goauth.IdentifierInput{Scheme: "probe_login", Value: "set-"+goauth.NewSubjectID().String()},
  Password: hostProbePassword,
 })
 if err != nil { t.Fatal(err) }
 cleanupHostProbeSubject(t, runtime.Database(), account.Subject.ID)
 stop := errors.New("host event rejected")
 for _, rollback := range []bool{true, false} {
  err = runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
   updated, err := runtime.SetTrustedLocalPassword(ctx, goauth.SetTrustedLocalPasswordRequest{
    SubjectID: account.Subject.ID, NewPassword: hostProbePassword,
   })
   if err != nil { return err }
   if updated.PrimaryEmail.ID != "" || updated.Subject.SecurityVersion != account.Subject.SecurityVersion+1 {
    return errors.New("trusted password set returned incorrect state")
   }
   executor, err := runtime.SQLExecutor(ctx)
   if err != nil { return err }
   if _, err := executor.ExecContext(ctx,
    "INSERT INTO "+projection+" VALUES($1,'password-set')", updated.Subject.ID); err != nil {
    return err
   }
   if rollback { return stop }
   return nil
  })
  expectedVersion := account.Subject.SecurityVersion+1
  expectedRows := 1
  if rollback {
   expectedVersion = account.Subject.SecurityVersion
   expectedRows = 0
   if !errors.Is(err, stop) { t.Fatalf("unexpected rollback error: %v", err) }
  } else if err != nil { t.Fatal(err) }
  stored, err := runtime.GetAccount(t.Context(), account.Subject.ID)
  if err != nil { t.Fatal(err) }
  if stored.Subject.SecurityVersion != expectedVersion { t.Fatal("password set escaped host commit boundary") }
  if got := hostProbeCount(t, runtime.Database(), "SELECT count(*) FROM "+projection); got != expectedRows {
   t.Fatalf("host event rows: %d", got)
  }
  if got := hostProbeCount(t, runtime.Database(),
   "SELECT count(*) FROM auth_security_audit_events WHERE subject_id=$1 AND event_type='password.trusted_set'",
   account.Subject.ID); got != expectedRows { t.Fatalf("password set audit rows: %d", got) }
 }
}
`
