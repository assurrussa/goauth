package externalconsumerprobe

const notificationOutcomeProbeTest = `
func TestNotificationOutcomeSurfaceExternalConsumer(t *testing.T) {
 var expire func(*postgres.Runtime, context.Context, int) (int64, error) = (*postgres.Runtime).ExpireNotifications
 if !errors.Is(errors.Join(goauth.ErrNotificationRejected, errors.New("synthetic")), goauth.ErrNotificationRejected) {
  t.Fatal("terminal rejection cannot be preserved by wrapping")
 }
 if _, err := expire(nil, t.Context(), 1); err == nil {
  t.Fatal("expiry accepted an uninitialized Runtime")
 }
}
`
