package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/assurrussa/goauth"
)

type NotificationWorkerConfig struct {
	Workers       int
	PollInterval  time.Duration
	SendTimeout   time.Duration
	LeaseDuration time.Duration
	RetryMin      time.Duration
	RetryMax      time.Duration
	MaxAttempts   int
	// OnBlocked receives a safe diagnostic after a decrypt failure is persisted.
	// It should return promptly; the worker continues with other deliveries.
	OnBlocked func(NotificationBlockedEvent)
}

// NotificationBlockedEvent contains no payload, key material, or raw error.
type NotificationBlockedEvent struct {
	DeliveryID string
	Reason     string
}

func (c NotificationWorkerConfig) withDefaults() (NotificationWorkerConfig, error) {
	if c.Workers == 0 {
		c.Workers = 1
	}
	if c.PollInterval == 0 {
		c.PollInterval = time.Second
	}
	if c.SendTimeout == 0 {
		c.SendTimeout = 10 * time.Second
	}
	if c.LeaseDuration == 0 {
		c.LeaseDuration = 30 * time.Second
	}
	if c.RetryMin == 0 {
		c.RetryMin = time.Second
	}
	if c.RetryMax == 0 {
		c.RetryMax = time.Minute
	}
	if c.MaxAttempts == 0 {
		c.MaxAttempts = 10
	}
	if c.Workers < 1 || c.Workers > 32 || c.PollInterval < 10*time.Millisecond ||
		c.SendTimeout <= 0 || c.LeaseDuration <= c.SendTimeout ||
		c.RetryMin <= 0 || c.RetryMax < c.RetryMin || c.MaxAttempts < 1 || c.MaxAttempts > 100 {
		return NotificationWorkerConfig{}, errors.New("invalid notification worker configuration")
	}
	return c, nil
}

type NotificationQueueStats struct {
	Pending   int64
	Leased    int64
	Blocked   int64
	Delivered int64
	// Exhausted includes an exhausted retry budget or explicit terminal sender rejection.
	Exhausted      int64
	Expired        int64
	OldestQueuedAt *time.Time
	WorkerRunning  bool
}

// NotificationStats reports delivery states without exposing encrypted
// payloads or raw sender errors.
func (r *Runtime) NotificationStats(ctx context.Context) (NotificationQueueStats, error) {
	if r == nil || r.store == nil {
		return NotificationQueueStats{}, errors.New("PostgreSQL Runtime is not initialized")
	}
	stats, err := r.store.notificationCounts(ctx)
	stats.WorkerRunning = r.notificationRunning.Load()
	return stats, err
}

// RunNotifications delivers queued events until ctx is cancelled. Separate
// Runtime instances may run this method concurrently against the same database.
// A stable delivery ID permits host senders to deduplicate at-least-once sends.
func (r *Runtime) RunNotifications(ctx context.Context) error {
	if r == nil || r.store == nil || r.notificationSender == nil {
		return errors.New("managed notification sender is not configured")
	}
	if !r.notificationRunning.CompareAndSwap(false, true) {
		return errors.New("notification worker is already running")
	}
	defer r.notificationRunning.Store(false)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var group sync.WaitGroup
	errorsCh := make(chan error, r.notificationWorker.Workers)
	for range r.notificationWorker.Workers {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := r.notificationLoop(ctx); err != nil && ctx.Err() == nil {
				select {
				case errorsCh <- err:
				default:
				}
				cancel()
			}
		}()
	}
	group.Wait()
	select {
	case err := <-errorsCh:
		return err
	default:
		return nil
	}
}

func (r *Runtime) notificationLoop(ctx context.Context) error {
	for ctx.Err() == nil {
		claim, err := r.store.claimNotification(ctx, r.notificationNow().UTC(), r.notificationWorker.LeaseDuration)
		if errors.Is(err, sql.ErrNoRows) {
			timer := time.NewTimer(r.notificationWorker.PollInterval)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return nil
			case <-timer.C:
				continue
			}
		}
		if ctx.Err() != nil {
			break
		}
		if err != nil {
			return fmt.Errorf("claim managed notification: %w", err)
		}
		deliveryErr := r.deliverNotification(ctx, claim)
		if ctx.Err() != nil {
			break
		}
		if deliveryErr != nil {
			return deliveryErr
		}
	}
	return ctx.Err()
}

func (r *Runtime) deliverNotification(ctx context.Context, claim notificationClaim) error {
	now := r.notificationNow().UTC()
	if claim.attempts >= r.notificationWorker.MaxAttempts {
		return r.store.finishNotification(ctx, claim, notificationExhausted, "sender", time.Time{})
	}
	current, err := r.store.notificationCurrent(ctx, claim.event, now)
	if err != nil {
		return fmt.Errorf("check queued notification: %w", err)
	}
	if !current {
		return r.store.finishNotification(ctx, claim, notificationExpired, "stale", time.Time{})
	}
	notification, err := r.DecryptNotificationEvent(claim.event)
	if err != nil {
		failure := "decrypt"
		if errors.Is(err, goauth.ErrKeyRingInvalid) {
			failure = "key_unavailable"
		}
		finished, err := r.store.finishNotificationResult(ctx, claim, notificationBlocked, failure, now.Add(time.Minute))
		if err != nil {
			return err
		}
		if finished && r.notificationWorker.OnBlocked != nil {
			r.notificationWorker.OnBlocked(NotificationBlockedEvent{DeliveryID: claim.event.ID, Reason: failure})
		}
		return nil
	}
	// ValidUntil belongs to the configured clock, which may be fixed or offset
	// from wall time. Translate its remaining validity to a relative timeout.
	now = r.notificationNow().UTC()
	remaining := claim.event.ValidUntil.Sub(now)
	if remaining <= 0 {
		return r.store.finishNotification(ctx, claim, notificationExpired, "stale", time.Time{})
	}
	sendCtx, cancel := context.WithTimeout(ctx, min(r.notificationWorker.SendTimeout, remaining))
	defer cancel()
	reserved, err := r.store.reserveNotificationSend(sendCtx, claim, r.notificationWorker.MaxAttempts,
		now, r.notificationWorker.LeaseDuration)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		if sendCtx.Err() != nil && notificationReservationCancelled(err) {
			// Cancellation can race the reservation's commit. Read the persisted
			// budget rather than assuming whether this attempt was counted.
			return r.finishNotificationSendFailure(ctx, claim)
		}
		return err
	}
	if !reserved {
		return nil // The lease was lost before the sender call.
	}
	if sendCtx.Err() != nil {
		return r.finishNotificationSendFailure(ctx, claim)
	}
	err = r.notificationSender.SendNotification(sendCtx, goauth.NotificationDelivery{
		ID: claim.event.ID, Notification: notification, ValidUntil: claim.event.ValidUntil, EncryptedEvent: claim.event,
	})
	cancel()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil {
		return r.store.finishNotification(ctx, claim, notificationDelivered, "", time.Time{})
	}
	if errors.Is(err, goauth.ErrNotificationRejected) {
		return r.store.finishNotification(ctx, claim, notificationExhausted, "sender_rejected", time.Time{})
	}
	// A successful reservation counted this attempt before calling the sender.
	claim.attempts++
	return r.settleNotificationSendFailure(ctx, claim)
}

// pgx cancel-request handlers can return PostgreSQL query_canceled instead of
// wrapping a context error. The caller also requires the send context to be done.
func notificationReservationCancelled(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "57014"
}

func (r *Runtime) finishNotificationSendFailure(ctx context.Context, claim notificationClaim) error {
	err := r.store.db.QueryRowContext(ctx, `
SELECT attempts FROM auth_notification_deliveries
WHERE id = $1 AND lease_token = $2 AND state = 'leased'`,
		claim.event.ID, claim.leaseToken).Scan(&claim.attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // A newer lease owner or cleanup owns the delivery now.
	}
	if err != nil {
		return fmt.Errorf("check managed notification send budget: %w", err)
	}
	return r.settleNotificationSendFailure(ctx, claim)
}

func (r *Runtime) settleNotificationSendFailure(ctx context.Context, claim notificationClaim) error {
	completedAt := r.notificationNow().UTC()
	if !completedAt.Before(claim.event.ValidUntil) {
		return r.store.finishNotification(ctx, claim, notificationExpired, "stale", time.Time{})
	}
	if claim.attempts >= r.notificationWorker.MaxAttempts {
		return r.store.finishNotification(ctx, claim, notificationExhausted, "sender", time.Time{})
	}
	// Backoff is indexed by the preceding attempt count, as on sender failure.
	previousAttempts := max(claim.attempts-1, 0)
	return r.store.finishNotification(ctx, claim, notificationPending, "sender",
		completedAt.Add(notificationBackoff(r.notificationWorker, previousAttempts)))
}

func notificationBackoff(config NotificationWorkerConfig, attempts int) time.Duration {
	delay := config.RetryMin
	for i := 0; i < attempts && delay < config.RetryMax; i++ {
		if delay > config.RetryMax/2 {
			return config.RetryMax
		}
		delay *= 2
	}
	if delay > config.RetryMax {
		return config.RetryMax
	}
	return delay
}
