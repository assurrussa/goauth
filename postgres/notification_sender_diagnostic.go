package postgres

import (
	"errors"

	"github.com/assurrussa/goauth"
)

const (
	senderOutcomeNotSent      = "not_sent"
	senderOutcomeUnknown      = "unknown"
	senderOutcomeRejected     = "rejected"
	senderOutcomeSimulated    = "simulated"
	senderCodeUnauthorized    = "unauthorized"
	senderCodeInvalidResponse = "invalid_response"
)

// Never inspect Error(), bodies, URLs or arbitrary sender attributes. Even an
// implementation of the optional interface is untrusted at this boundary.
func notificationSenderDiagnostic(err error) *goauth.NotificationDiagnostic {
	if err == nil {
		return nil
	}
	var source goauth.NotificationDiagnosticError
	if !errors.As(err, &source) {
		return nil
	}
	diagnostic := source.NotificationDiagnostic()
	terminal := diagnostic.Outcome == senderOutcomeRejected || diagnostic.Outcome == senderOutcomeSimulated
	if terminal != errors.Is(err, goauth.ErrNotificationRejected) || !validNotificationDiagnostic(diagnostic) {
		return nil
	}
	return &diagnostic
}

func validNotificationDiagnostic(d goauth.NotificationDiagnostic) bool {
	status := d.HTTPStatus
	switch d.Outcome {
	case senderOutcomeNotSent:
		switch d.Code {
		case "invalid_request":
			return status == 0 || status == 400
		case "context_done":
			return status == 0
		case "expired":
			return status == 0 || status == 410
		case "idempotency_conflict":
			return status == 409
		case senderCodeUnauthorized:
			return status == 401 || status == 403
		case "endpoint_unavailable":
			return status == 404 || status == 405
		case "request_too_large":
			return status == 413
		case "quota_exceeded":
			return status == 429
		}
	case senderOutcomeUnknown:
		return validUnknownNotificationDiagnostic(d)
	case "retryable":
		return status == 503 && (d.Code == "retry" || d.Code == "provider_rejected_temporary")
	case senderOutcomeRejected:
		return status == 422 && (d.Code == "failed" || d.Code == "provider_rejected" ||
			d.Code == "recipient_suppressed" || d.Code == "retry_budget_exhausted")
	case senderOutcomeSimulated:
		return status == 200 && (d.Code == senderOutcomeSimulated || d.Code == "dry_run_no_external_delivery")
	}
	return false
}

func validUnknownNotificationDiagnostic(d goauth.NotificationDiagnostic) bool {
	status := d.HTTPStatus
	switch d.Code {
	case "request_failed":
		return status == 0
	case "dispatching", "dispatch_in_progress":
		return status == 202
	case senderOutcomeUnknown, "dispatch_outcome_unknown":
		return status == 409
	case senderCodeInvalidResponse:
		switch status {
		case 400, 401, 403, 404, 405, 410, 413, 429:
			return false
		}
		return status >= 100 && status <= 599
	}
	return false
}
