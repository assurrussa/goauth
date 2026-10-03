// Package identifierbounds enforces portable custom identifier storage bounds.
package identifierbounds

import (
	"strings"
	"unicode/utf8"
)

// Valid reports whether a value can be stored in a bounded PostgreSQL TEXT key.
func Valid(value string) bool {
	return len(value) > 0 && len(value) <= 256 && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}
