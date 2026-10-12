package goauth

import (
	"context"
	"errors"
)

const passwordResetScopeDataKey = "password_reset_scope"

type passwordResetScopeContextKey struct{}

// WithPasswordResetScope binds a host-selected recovery authority to an operation.
// Callers must select scope from trusted route/configuration, never request fields.
// Empty scope preserves the legacy unscoped token purpose. A scoped token cannot
// be consumed in another scope, including the legacy empty scope.
func WithPasswordResetScope(ctx context.Context, scope string) (context.Context, error) {
	if ctx == nil || !validPasswordResetScope(scope) {
		return nil, errors.New("invalid password reset scope")
	}
	return context.WithValue(ctx, passwordResetScopeContextKey{}, scope), nil
}

// PasswordResetScope returns the trusted scope of the current recovery operation.
// Recipient policies must reject scopes they do not explicitly support.
func PasswordResetScope(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	scope, _ := ctx.Value(passwordResetScopeContextKey{}).(string)
	return scope
}

func validPasswordResetScope(scope string) bool {
	if len(scope) > 64 {
		return false
	}
	for _, ch := range scope {
		if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' && ch != '_' && ch != '.' {
			return false
		}
	}
	return true
}

func passwordResetPurpose(ctx context.Context) string {
	scope := PasswordResetScope(ctx)
	if scope == "" {
		return passwordResetSecretPurpose
	}
	return passwordResetSecretPurpose + ":scope:v1:" + scope
}

func passwordResetNotificationData(ctx context.Context, data map[string]string) map[string]string {
	scope := PasswordResetScope(ctx)
	if scope == "" {
		return data
	}
	if data == nil {
		data = make(map[string]string, 1)
	}
	data[passwordResetScopeDataKey] = scope
	return data
}

// PasswordResetNotificationContext restores only the authenticated notification
// scope. Use it after DecryptNotificationEvent, never on untrusted input. Missing
// metadata explicitly restores the legacy empty scope instead of inheriting a
// worker's ambient scope. Malformed metadata fails closed.
func PasswordResetNotificationContext(ctx context.Context, notification Notification) (context.Context, error) {
	return WithPasswordResetScope(ctx, notification.Data[passwordResetScopeDataKey])
}
