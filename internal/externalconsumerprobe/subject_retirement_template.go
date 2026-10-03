package externalconsumerprobe

const subjectRetirementProbeTest = `
func TestSubjectRetirementExternalConsumer(t *testing.T) {
 fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
  config.IdentifierResolvers = map[goauth.IdentifierScheme]goauth.IdentifierResolver{
   "retirement_probe": goauth.IdentifierResolverFunc(func(
 _ context.Context, in goauth.IdentifierInput,
) (goauth.IdentifierInput, error) {
    return in, nil
   }),
  }
 })
 if err != nil { t.Fatal(err) }
 var reader goauth.SubjectLifecycleReader = fixture.Store
 var retirement goauth.LocalIdentityRetirementStore = fixture.Store
 _, _ = reader, retirement
 login := goauth.IdentifierInput{Scheme: "retirement_probe", Value: "RetirementConsumer"}
 account, err := fixture.Runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
  Identifier: login, Password: "Retirement-Consumer-Synthetic-Passphrase-42",
 })
 if err != nil { t.Fatal(err) }
 before, err := fixture.Runtime.GetSubjectLifecycle(t.Context(), account.Subject.ID)
 if err != nil || before.RetiredAt != nil { t.Fatalf("initial lifecycle: %v", err) }
 request := goauth.RetireLocalIdentityRequest{
  SubjectID: account.Subject.ID, ExpectedIdentifier: login, ExpectedSecurityVersion: account.Subject.SecurityVersion,
 }
 view, err := fixture.Runtime.RetireLocalIdentity(t.Context(), request)
 if err != nil { t.Fatal(err) }
 if view.RetiredAt == nil || view.Account.Subject.ID != account.Subject.ID ||
  view.Account.Subject.Status != goauth.SubjectStatusDisabled ||
  view.Account.Subject.SecurityVersion != account.Subject.SecurityVersion+1 {
  t.Fatal("invalid terminal lifecycle result")
 }
 read, err := fixture.Runtime.GetSubjectLifecycle(t.Context(), account.Subject.ID)
 if err != nil || read.RetiredAt == nil || !read.RetiredAt.Equal(*view.RetiredAt) { t.Fatalf("persisted lifecycle: %v", err) }
 if _, err := fixture.Runtime.SetSubjectStatus(
 t.Context(), account.Subject.ID, goauth.SubjectStatusActive,
); !errors.Is(err, goauth.ErrSubjectRetired) {
  t.Fatalf("retired subject revived: %v", err)
 }
 if _, err := fixture.Runtime.RetireLocalIdentity(t.Context(), request); !errors.Is(err, goauth.ErrSubjectRetired) {
  t.Fatalf("repeated retirement: %v", err)
 }
 replacement, err := fixture.Runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
  Identifier: login, Password: "Retirement-Consumer-Synthetic-Passphrase-42",
 })
 if err != nil || replacement.Subject.ID == account.Subject.ID { t.Fatalf("replacement identity: %v", err) }
}
`

const subjectRetirementPostgresProbeTest = `
func TestSubjectRetirementManagedExternalConsumer(t *testing.T) {
 runtime := newHostProbeRuntime(t, true)
 projection := hostProbeProjection(t, runtime.Database())
 login := goauth.IdentifierInput{Scheme: "probe_login", Value: "retirement-"+goauth.NewSubjectID().String()}
 account, err := runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
 Identifier: login, Password: hostProbePassword,
})
 if err != nil { t.Fatal(err) }
 cleanupHostProbeSubject(t, runtime.Database(), account.Subject.ID)
 request := goauth.RetireLocalIdentityRequest{
  SubjectID: account.Subject.ID, ExpectedIdentifier: login, ExpectedSecurityVersion: account.Subject.SecurityVersion,
 }
 stop := errors.New("host retirement receipt failed")
 for _, rollback := range []bool{true, false} {
  var provisional goauth.SubjectLifecycleView
  err = runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
   var err error
   provisional, err = runtime.RetireLocalIdentity(ctx, request)
   if err != nil { return err }
   current, err := runtime.GetSubjectLifecycle(ctx, account.Subject.ID)
   if err != nil { return err }
   if current.RetiredAt == nil || provisional.RetiredAt == nil || !current.RetiredAt.Equal(*provisional.RetiredAt) {
    return errors.New("managed lifecycle lost persisted retirement")
   }
   executor, err := runtime.SQLExecutor(ctx)
   if err != nil { return err }
   if _, err = executor.ExecContext(ctx,
 "INSERT INTO "+projection+" VALUES($1,'subject-retired')", account.Subject.ID); err != nil {
 return err
}
   if rollback { return stop }
   return nil
  })
  current, readErr := runtime.GetSubjectLifecycle(t.Context(), account.Subject.ID)
  if readErr != nil { t.Fatal(readErr) }
  expectedRows := 1
  if rollback {
   if !errors.Is(err, stop) || current.RetiredAt != nil ||
    current.Account.Subject.SecurityVersion != account.Subject.SecurityVersion {
    t.Fatalf("retirement escaped rollback: %v", err)
   }
   expectedRows = 0
  } else {
   if err != nil || current.RetiredAt == nil || !current.RetiredAt.Equal(*provisional.RetiredAt) ||
    current.Account.Subject.Status != goauth.SubjectStatusDisabled { t.Fatalf("terminal commit: %v", err) }
  }
  if rows := hostProbeCount(t, runtime.Database(), "SELECT count(*) FROM "+projection); rows != expectedRows {
 t.Fatal("host receipt escaped transaction")
}
 }
 replacement, err := runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
 Identifier: login, Password: hostProbePassword,
})
 if err != nil { t.Fatal(err) }
 cleanupHostProbeSubject(t, runtime.Database(), replacement.Subject.ID)
 if replacement.Subject.ID == account.Subject.ID { t.Fatal("released login adopted terminal UUID") }
}
`
