//nolint:testpackage // Exercises the package-private public error mapping boundary.
package fiber

import (
	"fmt"
	"testing"

	"github.com/assurrussa/goauth"
)

func TestMFAErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{goauth.ErrMFARequired, 401, "mfa_required"},
		{goauth.ErrMFALoginDenied, 401, "mfa_login_denied"},
		{goauth.ErrMFAUnavailable, 503, "mfa_unavailable"},
	} {
		status, code, _ := mapError(fmt.Errorf("wrapped: %w", tc.err))
		if status != tc.status || code != tc.code {
			t.Fatalf("got %d %s", status, code)
		}
	}
}
