package externalconsumerprobe

const rateEventCleanupProbeTest = `
func TestRateEventCleanupSurfaceExternalConsumer(t *testing.T) {
 request := postgres.RateLimitCleanupRequest{Before: time.Time{}, Limit: 1}
 var cleanup func(*postgres.Runtime,context.Context,postgres.RateLimitCleanupRequest)(int64,error) =
  (*postgres.Runtime).CleanupRateLimitEvents
 count, err := cleanup(nil,t.Context(),request)
 if err == nil || count != 0 { t.Fatal("uninitialized cleanup must fail without a successful count") }
}
func TestBroadCleanupSurfaceExternalConsumer(t *testing.T) {
 var cleanup func(*postgres.Runtime,context.Context,postgres.CleanupPolicy,int)(postgres.CleanupBatchResult,error) =
  (*postgres.Runtime).CleanupBatch
 result, err := cleanup(nil,t.Context(),postgres.CleanupPolicy{},1)
 if err == nil || result != (postgres.CleanupBatchResult{}) {
  t.Fatal("uninitialized bounded broad cleanup must reject with no confirmed counts")
 }
 _ = postgres.CleanupBatchResult{CleanupResult:postgres.CleanupResult{},OIDCRequests:0,OIDCCodes:0}
}
`

const rateEventCleanupPostgresProbeTest = `
func TestRateEventCleanupManagedExternalConsumer(t *testing.T) {
 runtime := newHostProbeRuntime(t, true)
 db := runtime.Database()
 cutoff := time.Date(1900,1,2,0,0,0,0,time.UTC)
 // Use an ancient, preflighted range to avoid removing unrelated fixture events.
 if hostProbeCount(t, db, "SELECT count(*) FROM auth_rate_limit_events WHERE occurred_at < $1", cutoff) != 0 {
  t.Fatal("rate retention consumer requires its ancient fixture range to be empty")
 }
 action := "cleanup-"+goauth.NewSubjectID().String()
 t.Cleanup(func() {
  if _, err := db.ExecContext(context.Background(), "DELETE FROM auth_rate_limit_events WHERE action=$1", action); err != nil {
   t.Errorf("remove owned rate fixture: %v",err)
  }
 })
 for _, at := range []time.Time{cutoff.Add(-time.Hour),cutoff.Add(-time.Hour),cutoff.Add(-time.Hour),cutoff} {
  if _, err := db.ExecContext(t.Context(),
 "INSERT INTO auth_rate_limit_events(key_id,bucket_digest,action,occurred_at) "+
 "VALUES('probe',decode(repeat('00',32),'hex'),$1,$2)",
 action,at); err != nil { t.Fatal(err) }
 }
 request := postgres.RateLimitCleanupRequest{Before:cutoff,Limit:2}
 if count, err := runtime.CleanupRateLimitEvents(t.Context(), request); err != nil || count != 2 {
  t.Fatalf("bounded committed cleanup: count=%d err=%v",count,err)
 }
 if err := runtime.InAuthTransaction(t.Context(),func(ctx context.Context) error {
  if count, err := runtime.CleanupRateLimitEvents(ctx,request); err == nil || count != 0 {
   return errors.New("cleanup joined an active transaction")
  }
  return nil
 }); err != nil { t.Fatal(err) }
 if count, err := runtime.CleanupRateLimitEvents(t.Context(),request); err != nil || count != 1 {
  t.Fatalf("remaining committed cleanup: count=%d err=%v",count,err)
 }
 if hostProbeCount(t,db,"SELECT count(*) FROM auth_rate_limit_events WHERE action=$1 AND occurred_at=$2",action,cutoff) != 1 {
  t.Fatal("exclusive cutoff event was deleted")
 }
 if count, err := runtime.CleanupRateLimitEvents(t.Context(),postgres.RateLimitCleanupRequest{}); err == nil || count != 0 {
  t.Fatal("zero cleanup bound was accepted")
 }
}

func TestBroadCleanupManagedScopeExternalConsumer(t *testing.T) {
 runtime := newHostProbeRuntime(t, true)
 if err := runtime.InAuthTransaction(t.Context(),func(ctx context.Context) error {
  result, err := runtime.CleanupBatch(ctx,postgres.CleanupPolicy{},1)
  if !errors.Is(err,postgres.ErrAuthTransactionAlreadyActive) || result != (postgres.CleanupBatchResult{}) {
   return errors.New("bounded broad cleanup must reject an ambient transaction before any phase")
  }
  return nil
 }); err != nil { t.Fatal(err) }
 result, err := runtime.CleanupBatch(t.Context(),postgres.CleanupPolicy{},0)
 if err == nil || result != (postgres.CleanupBatchResult{}) {
  t.Fatal("zero broad cleanup bound was accepted")
 }
}
`
