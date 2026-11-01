package postgres //nolint:testpackage // Exercise receipt ownership and protocol fencing through the synthetic driver.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

const (
	notificationGatewayTestReceipt = "receipt-1"
	gatewayTestProtocol            = "notifyhub_queue_v1"
	gatewayLegacyAccepted          = "accepted"
	gatewayLegacyOtherProtocol     = "other_protocol"
	gatewayLegacyRevoked           = "revoked"
	gatewayLegacyLateLease         = "late_lease"
	gatewayLegacyDeadline          = "deadline"
	gatewayLegacyPasswordReset     = "password_reset"
)

type gatewayTestSender struct {
	sends, checks int
	outcome       error
}

func (s *gatewayTestSender) SendNotification(context.Context, goauth.NotificationDelivery) error {
	s.sends++
	return &goauth.NotificationQueuedError{ReceiptID: notificationGatewayTestReceipt}
}

func (s *gatewayTestSender) ReconcileNotification(_ context.Context, r goauth.NotificationQueueReceipt) error {
	s.checks++
	if r.ReceiptID != notificationGatewayTestReceipt {
		return errors.New("wrong receipt")
	}
	return s.outcome
}

func TestGatewayOwnershipDoesNotMeanProviderAcceptance(t *testing.T) {
	now := time.Date(2026, 10, 31, 18, 0, 0, 0, time.UTC)
	sender := &gatewayTestSender{outcome: &goauth.NotificationQueuedError{ReceiptID: notificationGatewayTestReceipt}}
	d := &deadlineDriver{}
	r := deadlineRuntime(t, d, sender)
	r.notificationNow = func() time.Time { return now }
	event := deadlineEvent(t, "gateway-owned", now.Add(time.Hour))
	d.deliveries = []deadlineDelivery{{event: event, token: notificationClockLease, state: notificationLeased}}
	claim := notificationClaim{event: event, leaseToken: notificationClockLease}
	require.NoError(t, r.deliverNotification(context.Background(), claim))
	require.Equal(t, notificationQueued, d.deliveries[0].state)
	require.True(t, d.deliveries[0].cleared)
	require.False(t, d.deliveries[0].delivered)
	require.Equal(t, 1, sender.sends)
	require.EqualValues(t, 1, d.deliveries[0].attempts)
	claim.receiptID = notificationGatewayTestReceipt
	claim.attempts = 100 // Reconciling is not a new send attempt.
	for _, outcome := range []error{
		&goauth.NotificationQueuedError{ReceiptID: notificationGatewayTestReceipt},
		errors.New("observation failed"), &goauth.NotificationQueuedError{ReceiptID: "mismatched"},
		goauth.ErrNotificationRejected,
	} {
		d.deliveries[0].state = notificationLeased
		d.deliveries[0].token = notificationClockLease
		sender.outcome = outcome
		require.NoError(t, r.deliverNotification(context.Background(), claim))
		require.Equal(t, notificationQueued, d.deliveries[0].state)
	}
	d.deliveries[0].state = notificationLeased
	d.deliveries[0].token = notificationClockLease
	sender.outcome = nil
	require.NoError(t, r.deliverNotification(context.Background(), claim))
	require.Equal(t, notificationDelivered, d.deliveries[0].state)
	require.Equal(t, 1, sender.sends)
	require.Equal(t, 5, sender.checks)
	require.EqualValues(t, 1, d.deliveries[0].attempts)
}

func TestTransportProtocolChangeFencesLegacyBeforeSend(t *testing.T) {
	sender := &gatewayTestSender{}
	d := &deadlineDriver{}
	r := deadlineRuntime(t, d, sender)
	r.store.notificationProtocol = gatewayTestProtocol
	event := deadlineEvent(t, "legacy-held", time.Now().Add(time.Hour))
	d.deliveries = []deadlineDelivery{{event: event, token: notificationClockLease, state: notificationLeased}}
	claim := notificationClaim{event: event, leaseToken: notificationClockLease}
	require.NoError(t, r.deliverNotification(context.Background(), claim))
	require.Equal(t, notificationBlocked, d.deliveries[0].state)
	require.Zero(t, sender.sends)
	require.Zero(t, sender.checks)
	require.Zero(t, d.deliveries[0].attempts)
	require.False(t, d.deliveries[0].cleared)
}

func TestGatewayTerminalFailureDoesNotClaimSynchronousRejection(t *testing.T) {
	sender := &gatewayTestSender{outcome: goauth.ErrNotificationQueueFailed}
	d := &deadlineDriver{}
	r := deadlineRuntime(t, d, sender)
	event := deadlineEvent(t, "terminal-gateway", time.Now().Add(time.Hour))
	d.deliveries = []deadlineDelivery{{
		event: event, token: notificationClockLease, state: notificationLeased,
		receiptID: notificationGatewayTestReceipt, attempts: 1,
	}}
	claim := notificationClaim{
		event: event, leaseToken: notificationClockLease, receiptID: notificationGatewayTestReceipt, attempts: 1,
	}
	require.NoError(t, r.deliverNotification(context.Background(), claim))
	require.Equal(t, notificationExhausted, d.deliveries[0].state)
	require.False(t, d.deliveries[0].delivered)
	require.Zero(t, sender.sends)
	require.EqualValues(t, 1, d.deliveries[0].attempts)
}

type cancelledGatewaySender struct {
	cancel context.CancelFunc
	checks int
}

func (*cancelledGatewaySender) SendNotification(context.Context, goauth.NotificationDelivery) error {
	return errors.New("unexpected submit")
}

func (s *cancelledGatewaySender) ReconcileNotification(context.Context, goauth.NotificationQueueReceipt) error {
	s.checks++
	s.cancel()
	return nil
}

func TestGatewayCancellationDoesNotAcknowledgeOrResubmit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sender := &cancelledGatewaySender{cancel: cancel}
	d := &deadlineDriver{}
	r := deadlineRuntime(t, d, sender)
	event := deadlineEvent(t, "cancelled-gateway", time.Now().Add(time.Hour))
	d.deliveries = []deadlineDelivery{{
		event: event, token: notificationClockLease, state: notificationLeased,
		receiptID: notificationGatewayTestReceipt, attempts: 1,
	}}
	claim := notificationClaim{
		event: event, leaseToken: notificationClockLease, receiptID: notificationGatewayTestReceipt, attempts: 1,
	}
	err := r.deliverNotification(ctx, claim)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, notificationLeased, d.deliveries[0].state)
	require.Equal(t, 1, sender.checks)
	require.False(t, d.deliveries[0].delivered)
	require.EqualValues(t, 1, d.deliveries[0].attempts)
}

type lateGatewayObserver struct {
	observe func(context.Context) error
}

func (*lateGatewayObserver) SendNotification(context.Context, goauth.NotificationDelivery) error {
	return errors.New("unexpected send after gateway ownership")
}

func (s *lateGatewayObserver) ReconcileNotification(ctx context.Context, _ goauth.NotificationQueueReceipt) error {
	return s.observe(ctx)
}

func TestGatewayLateObservationCannotReviveExpiredDelivery(t *testing.T) {
	for _, crossesExpiry := range []bool{false, true} {
		t.Run(map[bool]string{false: "child deadline", true: "original expiry"}[crossesExpiry], func(t *testing.T) {
			now := time.Now().UTC()
			deadline := now.Add(time.Hour)
			sender := &lateGatewayObserver{}
			driver := &deadlineDriver{}
			runtime := deadlineRuntime(t, driver, sender)
			runtime.notificationNow = func() time.Time { return now }
			runtime.notificationWorker.SendTimeout = time.Millisecond
			event := deadlineEvent(t, "late-gateway", deadline)
			claim := notificationClaim{
				event: event, leaseToken: notificationClockLease,
				receiptID: notificationGatewayTestReceipt, attempts: 1,
			}
			driver.deliveries = []deadlineDelivery{{
				event: event, token: notificationClockLease, state: notificationLeased,
				receiptID: notificationGatewayTestReceipt, attempts: 1,
			}}
			sender.observe = func(ctx context.Context) error {
				if crossesExpiry {
					now = deadline
				} else {
					<-ctx.Done()
				}
				return nil // Deliberately ignores its own ended observation window.
			}
			require.NoError(t, runtime.deliverNotification(context.Background(), claim))
			expected := notificationQueued
			if crossesExpiry {
				expected = notificationExpired
			}
			require.Equal(t, expected, driver.deliveries[0].state)
			require.False(t, driver.deliveries[0].delivered)
			require.EqualValues(t, 1, driver.deliveries[0].attempts)
		})
	}
}
