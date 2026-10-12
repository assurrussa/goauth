package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/assurrussa/goauth"
)

var errEmailChangeNotificationStale = errors.New("email change notification is stale")

func (r *Runtime) sendCurrentEmailChangeNotification(
	ctx context.Context, event goauth.EncryptedEvent, notification goauth.Notification,
) error {
	if event.Type != "email_change" {
		return r.sendCurrentPasswordResetNotification(ctx, event, notification)
	}
	// Scope must match both durable record and authenticated encrypted payload;
	// an omitted scope cannot downgrade a host challenge to the legacy sender.
	scope, err := r.emailChangeNotificationScope(ctx, event, notification)
	if err != nil {
		return err
	}
	ctx = goauth.WithEmailChangeScope(ctx, scope)
	if scope == "" {
		return r.sendCurrentPasswordResetNotification(ctx, event, notification)
	}
	target := r.emailChangeTargets[scope]
	if target == nil || notification.Template != event.Type {
		return errEmailChangeNotificationStale
	}
	return r.store.InAuthTransaction(ctx, func(txCtx context.Context) error {
		if err := r.validateScopedEmailDelivery(txCtx, event, notification, scope, target); err != nil {
			return err
		}
		if err := txCtx.Err(); err != nil {
			return err
		}
		// The caller's timeout bounds delivery while the subject lock excludes a
		// concurrent target/security change. Sender must honor this context.
		return r.notificationSender.SendNotification(txCtx, goauth.NotificationDelivery{
			ID: event.ID, Notification: notification, ValidUntil: event.ValidUntil, EncryptedEvent: event,
		})
	})
}

func (r *Runtime) emailChangeNotificationScope(ctx context.Context, event goauth.EncryptedEvent,
	notification goauth.Notification,
) (goauth.EmailChangeScope, error) {
	var persisted goauth.EmailChangeScope
	err := r.store.queryer(ctx).QueryRowContext(ctx, `
SELECT scope FROM auth_email_change_records WHERE id=$1 AND subject_id=$2`, event.ReferenceID, event.SubjectID).Scan(&persisted)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errEmailChangeNotificationStale
	}
	if err != nil {
		return "", err
	}
	if string(persisted) != notification.Data["email_change_scope"] {
		return "", errEmailChangeNotificationStale
	}
	return persisted, nil
}

func (r *Runtime) validateScopedEmailDelivery(ctx context.Context, event goauth.EncryptedEvent,
	notification goauth.Notification, scope goauth.EmailChangeScope, target goauth.EmailChangeTarget,
) error {
	account, err := r.store.LockAccount(ctx, event.SubjectID)
	if errors.Is(err, goauth.ErrAccountNotFound) || errors.Is(err, goauth.ErrSubjectRetired) {
		return errEmailChangeNotificationStale
	}
	if err != nil {
		return err
	}
	if account.Subject.Status != goauth.SubjectStatusActive {
		return errEmailChangeNotificationStale
	}
	now := r.notificationNow().UTC()
	current, err := r.store.notificationCurrent(ctx, event, now)
	if err != nil {
		return err
	}
	if !current {
		return errEmailChangeNotificationStale
	}
	pending, err := r.store.GetPendingScopedEmailChange(ctx, event.SubjectID, scope, now)
	if errors.Is(err, goauth.ErrEmailChangeNotFound) {
		return errEmailChangeNotificationStale
	}
	if err != nil {
		return err
	}
	recipient, err := goauth.NormalizeEmail(notification.To)
	if err != nil || pending.ID != event.ReferenceID || pending.Scope != scope ||
		pending.ExpectedSecurityVersion != account.Subject.SecurityVersion || recipient != pending.NewNormalizedValue {
		return errEmailChangeNotificationStale
	}
	snapshot, err := target.SnapshotEmailChangeTarget(ctx, event.SubjectID)
	if errors.Is(err, goauth.ErrAccountNotFound) || errors.Is(err, goauth.ErrAccountUnavailable) ||
		errors.Is(err, goauth.ErrSecurityVersionMismatch) {
		return errEmailChangeNotificationStale
	}
	if err != nil {
		return err
	}
	if snapshot != pending.TargetSnapshot {
		return errEmailChangeNotificationStale
	}
	return nil
}
