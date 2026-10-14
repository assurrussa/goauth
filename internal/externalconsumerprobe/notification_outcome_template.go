package externalconsumerprobe

const notificationOutcomeProbeTest = `
func TestNotificationOutcomeSurfaceExternalConsumer(t *testing.T) {
 var cancel func(*postgres.Runtime, context.Context, string) (bool, error) = (*postgres.Runtime).CancelNotification
 var cleanup func(*postgres.Runtime, context.Context, time.Duration, int) (int64, error) =
  (*postgres.Runtime).CleanupNotificationReceipts
 if changed, err := cancel(nil, t.Context(), "00000000-0000-4000-8000-000000000001"); changed || err == nil {
  t.Fatal("cancellation accepted an uninitialized Runtime")
 }
 if count, err := cleanup(nil, t.Context(), 0, 1); count != 0 || err == nil {
  t.Fatal("receipt cleanup accepted an uninitialized Runtime")
 }
 _ = postgres.NotificationQueueStats{Cancelled: 0}
 var expire func(*postgres.Runtime, context.Context, int) (int64, error) = (*postgres.Runtime).ExpireNotifications
 if !errors.Is(errors.Join(goauth.ErrNotificationRejected, errors.New("synthetic")), goauth.ErrNotificationRejected) {
  t.Fatal("terminal rejection cannot be preserved by wrapping")
 }
 if _, err := expire(nil, t.Context(), 1); err == nil {
  t.Fatal("expiry accepted an uninitialized Runtime")
 }
}
`
