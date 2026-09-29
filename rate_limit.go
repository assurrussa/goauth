package goauth

import "errors"

// ErrRateLimitTransactionUnsupported means attempt admission was invoked inside
// a managed auth transaction. Call the rate-limited Runtime operation before
// opening an outer AuthTransaction; do not strip the callback context to retry.
// The built-in stores reject this composition before consuming an attempt or
// verifying a password. This is a wiring error, not a throttling or credential
// failure. Transactional email-issue quotas are not affected.
var ErrRateLimitTransactionUnsupported = errors.New("rate-limit admission requires no active auth transaction")
