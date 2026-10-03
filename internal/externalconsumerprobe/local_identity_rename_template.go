package externalconsumerprobe

const localIdentityRenameProbeTest = `
func TestLocalIdentityRenameExternalConsumer(t *testing.T) {
 fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
  config.IdentifierResolvers = map[goauth.IdentifierScheme]goauth.IdentifierResolver{
   "probe_login": goauth.IdentifierResolverFunc(func(
 _ context.Context, input goauth.IdentifierInput,
 ) (goauth.IdentifierInput, error) { return input, nil }),
  }
 })
 if err != nil {
 t.Fatal(err) }
 var reader goauth.LocalIdentifierReader = fixture.Store
 var renamer goauth.LocalIdentityRenameStore = fixture.Store
 _, _ = reader, renamer
 account, err := fixture.Runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
  Identifier: goauth.IdentifierInput{Scheme: "probe_login", Value: "Original"}, Password: "Rename-Probe-Passphrase-42",
  Profile: goauth.BasicProfile{Username: "profile-only"},
 })
 if err != nil {
 t.Fatal(err) }
 original, err := fixture.Runtime.GetLocalIdentifier(t.Context(), account.Subject.ID, "probe_login")
 if err != nil {
 t.Fatal(err) }
 request := goauth.RenameLocalIdentityRequest{
  SubjectID: account.Subject.ID, ExpectedSecurityVersion: account.Subject.SecurityVersion,
  ExpectedIdentifier: goauth.IdentifierInput{Scheme: original.Scheme, Value: original.DisplayValue},
  NewIdentifier: goauth.IdentifierInput{Scheme: original.Scheme, Value: "original"},
 }
 var view goauth.LocalIdentityView
 view, err = fixture.Runtime.RenameLocalIdentity(t.Context(), request)
 if err != nil {
 t.Fatal(err) }
 if view.Account.Subject.ID != account.Subject.ID || view.Account.Profile != account.Profile ||
  view.Account.Subject.SecurityVersion != account.Subject.SecurityVersion+1 || view.Identifier.ID != original.ID ||
  view.Identifier.DisplayValue != "original" || view.Identifier.NormalizedValue != "original" {
  t.Fatal("rename lost canonical identity, profile or case-sensitive spelling")
 }
 current, err := fixture.Runtime.GetLocalIdentifier(t.Context(), account.Subject.ID, "probe_login")
 if err != nil || current.ID != view.Identifier.ID || current.DisplayValue != view.Identifier.DisplayValue {
 t.Fatalf("read rename: %v", err) }
 if _, err := fixture.Runtime.FindAccount(t.Context(), request.ExpectedIdentifier); !errors.Is(err, goauth.ErrAccountNotFound) {
  t.Fatalf("old login was retained: %v", err)
 }
 verified, err := fixture.Runtime.VerifyCredential(t.Context(), goauth.Credential{
 Identifier: request.NewIdentifier, Password: "Rename-Probe-Passphrase-42",
 })
 if err != nil || verified.Subject.ID != account.Subject.ID {
 t.Fatalf("renamed credential: %v", err) }
 if _, err := fixture.Runtime.RenameLocalIdentity(t.Context(), request); !errors.Is(err, goauth.ErrSecurityVersionMismatch) {
 t.Fatalf("stale rename: %v", err) }
 request.ExpectedSecurityVersion = view.Account.Subject.SecurityVersion
 request.ExpectedIdentifier = request.NewIdentifier
 if _, err := fixture.Runtime.RenameLocalIdentity(t.Context(), request); !errors.Is(err, goauth.ErrIdentifierUnchanged) {
 t.Fatalf("exact no-op: %v", err) }
 replacement, err := fixture.Runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
  Identifier: goauth.IdentifierInput{Scheme: "probe_login", Value: "Original"}, Password: "Rename-Probe-Passphrase-42",
 })
 if err != nil || replacement.Subject.ID == account.Subject.ID {
 t.Fatalf("old login adopted old identity: %v", err) }
}
`

const localIdentityRenamePostgresProbeTest = `
func TestLocalIdentityRenameManagedExternalConsumer(t *testing.T) {
 runtime := newHostProbeRuntime(t, true)
 projection := hostProbeProjection(t, runtime.Database())
 originalInput := goauth.IdentifierInput{Scheme: "probe_login", Value: "rename-"+goauth.NewSubjectID().String()}
 account, err := runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
 Identifier: originalInput, Password: hostProbePassword,
 })
 if err != nil {
 t.Fatal(err) }
 cleanupHostProbeSubject(t, runtime.Database(), account.Subject.ID)
 original, err := runtime.GetLocalIdentifier(t.Context(), account.Subject.ID, originalInput.Scheme)
 if err != nil {
 t.Fatal(err) }
 next := originalInput
 next.Value += "-new"
 request := goauth.RenameLocalIdentityRequest{
 SubjectID: account.Subject.ID, ExpectedSecurityVersion: account.Subject.SecurityVersion,
 ExpectedIdentifier: originalInput, NewIdentifier: next,
 }
 stop := errors.New("host receipt failed")
 for _, rollback := range []bool{true, false} {
  err = runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
   view, err := runtime.RenameLocalIdentity(ctx, request)
   if err != nil {
 return err
 }
   if view.Account.Subject.ID != account.Subject.ID || view.Identifier.ID != original.ID ||
 view.Account.Subject.SecurityVersion != account.Subject.SecurityVersion+1 {
    return errors.New("rename changed immutable identity or version incorrectly")
   }
   read, err := runtime.GetLocalIdentifier(ctx, account.Subject.ID, originalInput.Scheme)
   if err != nil {
 return err
 }
   if read.DisplayValue != next.Value { return errors.New("managed read missed provisional rename") }
   executor, err := runtime.SQLExecutor(ctx)
   if err != nil {
 return err
 }
   if _, err := executor.ExecContext(ctx,
 "INSERT INTO "+projection+" VALUES($1,'identity-renamed')", account.Subject.ID); err != nil {
 return err
 }
   if rollback { return stop }
   return nil
  })
  expectedName, expectedVersion, expectedRows := next.Value, account.Subject.SecurityVersion+1, 1
  if rollback {
   if !errors.Is(err, stop) {
 t.Fatalf("rollback: %v", err) }
   expectedName, expectedVersion, expectedRows = originalInput.Value, account.Subject.SecurityVersion, 0
  } else if err != nil {
 t.Fatal(err) }
  read, err := runtime.GetLocalIdentifier(t.Context(), account.Subject.ID, originalInput.Scheme)
  if err != nil || read.DisplayValue != expectedName {
 t.Fatalf("rename escaped host commit: %v", err) }
  stored, err := runtime.GetAccount(t.Context(), account.Subject.ID)
  if err != nil || stored.Subject.SecurityVersion != expectedVersion {
 t.Fatalf("version escaped host commit: %v", err) }
  if got := hostProbeCount(t, runtime.Database(), "SELECT count(*) FROM "+projection); got != expectedRows {
 t.Fatalf("host receipt rows: %d", got) }
  if got := hostProbeCount(t, runtime.Database(),
 "SELECT count(*) FROM auth_security_audit_events WHERE subject_id=$1 AND event_type='local_identity.renamed'",
 account.Subject.ID); got != expectedRows {
 t.Fatalf("rename audit rows: %d", got) }
 }
}
`
