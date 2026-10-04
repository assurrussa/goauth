package externalconsumerprobe

const ownedAuthTransactionProbeTest = `
func TestOwnedAuthTransactionSurfaceExternalConsumer(t *testing.T) {
 var transaction func(*postgres.Runtime, context.Context, func(context.Context) error) error =
  (*postgres.Runtime).InOwnedAuthTransaction
 var active error = postgres.ErrAuthTransactionAlreadyActive
 if !errors.Is(active, postgres.ErrAuthTransactionAlreadyActive) { t.Fatal("owned sentinel unavailable") }
 called := false
 if err := transaction(nil, t.Context(), func(context.Context) error { called = true; return nil }); err == nil || called {
  t.Fatal("uninitialized owned transaction must reject before callback")
 }
}
`

const ownedAuthTransactionPostgresProbeTest = `
func TestOwnedAuthTransactionManagedExternalConsumer(t *testing.T) {
 runtime := newHostProbeRuntime(t, true)
 foreign := newHostProbeRuntime(t, true) // Same DSN, distinct handle.
 db := runtime.Database()
 projection := hostProbeProjection(t, db)
 rejection := errors.New("owned host rollback")
 for _, abort := range []bool{true, false} {
  subject := goauth.NewSubjectID()
  prepared := ""
  err := runtime.InOwnedAuthTransaction(t.Context(), func(ctx context.Context) error {
   called := false
   if err := runtime.InOwnedAuthTransaction(ctx, func(context.Context) error { called = true; return nil });
    !errors.Is(err, postgres.ErrAuthTransactionAlreadyActive) || called {
    return errors.New("nested owned transaction was not rejected before callback")
   }
   if err := foreign.InOwnedAuthTransaction(ctx, func(context.Context) error { called = true; return nil });
    err == nil || errors.Is(err, postgres.ErrAuthTransactionAlreadyActive) || called {
    return errors.New("foreign same-DSN transaction was not rejected")
   }
   if err := runtime.InAuthTransaction(ctx, func(nested context.Context) error {
    executor, err := runtime.SQLExecutor(nested)
    if err != nil { return err }
    _, err = executor.ExecContext(nested, "INSERT INTO "+projection+"(subject_id) VALUES ($1)", subject)
    return err
   }); err != nil { return err }
   if hostProbeCount(t, db, "SELECT count(*) FROM "+projection+" WHERE subject_id=$1", subject) != 0 {
    return errors.New("legacy joining transaction committed early")
   }
   prepared = "provisional-response"
   if abort { return rejection }
   return nil
  })
  response := ""
  if err == nil { response = prepared }
  count := hostProbeCount(t, db, "SELECT count(*) FROM "+projection+" WHERE subject_id=$1", subject)
  if abort {
   if !errors.Is(err, rejection) || count != 0 || response != "" {
 t.Fatal("owned rollback exposed provisional response or writes")
 }
  } else if err != nil || count != 1 || response != "provisional-response" { t.Fatal("owned commit was not confirmed", err) }
 }
 if err := runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
  called := false
  err := runtime.InOwnedAuthTransaction(ctx, func(context.Context) error { called=true; return nil })
  if !errors.Is(err, postgres.ErrAuthTransactionAlreadyActive) || called {
 return errors.New("legacy ambient scope accepted owned call")
 }
  return nil
 }); err != nil { t.Fatal(err) }
}
`
