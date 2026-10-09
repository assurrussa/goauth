package postgres

import (
	"context"
	"errors"

	"github.com/assurrussa/goauth"
)

var errPasswordResetNotificationStale = errors.New("password reset notification is stale")

func (r *Runtime) sendCurrentPasswordResetNotification(
	ctx context.Context, event goauth.EncryptedEvent, notification goauth.Notification,
) error {
	send := func(sendCtx context.Context) error {
		return r.notificationSender.SendNotification(sendCtx, goauth.NotificationDelivery{
			ID: event.ID, Notification: notification, ValidUntil: event.ValidUntil, EncryptedEvent: event,
		})
	}
	if r.passwordResetRecipientResolver == nil ||
		(event.Type != "password_reset" && event.Type != "password_reset_success") {
		return send(ctx)
	}
	return r.store.InAuthTransaction(ctx, func(txCtx context.Context) error {
		account, err := r.store.LockAccount(txCtx, event.SubjectID)
		if errors.Is(err, goauth.ErrAccountNotFound) || errors.Is(err, goauth.ErrSubjectRetired) {
			return errPasswordResetNotificationStale
		}
		if err != nil {
			return err
		}
		if account.Subject.Status != goauth.SubjectStatusActive || notification.Template != event.Type {
			return errPasswordResetNotificationStale
		}
		local, err := r.store.GetLocalAccount(txCtx, event.SubjectID)
		if errors.Is(err, goauth.ErrAccountNotFound) {
			return errPasswordResetNotificationStale
		}
		if err != nil {
			return err
		}
		if local.PasswordPHC == "" || local.Account.Subject.ID != event.SubjectID {
			return errPasswordResetNotificationStale
		}
		// This read joins the transaction and follows the subject lock, so an
		// address change-away-and-back cannot revive a retired reset record.
		current, err := r.store.notificationCurrent(txCtx, event, r.notificationNow().UTC())
		if err != nil {
			return err
		}
		if !current {
			return errPasswordResetNotificationStale
		}
		if err := r.validatePasswordResetNotificationRecipient(txCtx, account, notification.To); err != nil {
			return err
		}
		// Keep the subject lock through the bounded sender call. Hosts must use
		// this context, including when their sender joins the auth transaction.
		if err := txCtx.Err(); err != nil {
			return err
		}
		return send(txCtx)
	})
}

func (r *Runtime) validatePasswordResetNotificationRecipient(
	ctx context.Context, account goauth.Account, address string,
) error {
	requested, err := goauth.NormalizeEmail(address)
	if err != nil {
		return errPasswordResetNotificationStale
	}
	recipient, err := r.passwordResetRecipientResolver.ResolvePasswordResetRecipient(ctx, account, requested)
	if errors.Is(err, goauth.ErrAccountNotFound) || errors.Is(err, goauth.ErrAccountUnavailable) ||
		errors.Is(err, goauth.ErrInvalidIdentifier) || errors.Is(err, goauth.ErrSecurityVersionMismatch) {
		return errPasswordResetNotificationStale
	}
	if err != nil {
		return err
	}
	resolved, err := goauth.NormalizeEmail(recipient)
	if err != nil || resolved != requested {
		return errPasswordResetNotificationStale
	}
	return nil
}
