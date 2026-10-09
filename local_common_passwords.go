package goauth

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// LocalCommonPasswordCheckerOption configures NewLocalCommonPasswordChecker.
// Use WithBuiltInCommonPasswords to include the default dictionary.
type LocalCommonPasswordCheckerOption func(*localCommonPasswordCheckerConfig)

type localCommonPasswordCheckerConfig struct {
	includeBuiltIns bool
}

// WithBuiltInCommonPasswords adds the existing built-in dictionary to a local
// checker. It does not modify the default dictionary or any other checker.
// Repeating this option has the same effect as supplying it once.
func WithBuiltInCommonPasswords() LocalCommonPasswordCheckerOption {
	return func(config *localCommonPasswordCheckerConfig) {
		config.includeBuiltIns = true
	}
}

// NewLocalCommonPasswordChecker copies passwords into an immutable in-memory
// dictionary implementing CommonPasswordChecker. It is safe for concurrent reads
// after construction; callers must not mutate passwords during construction.
//
// Entries and queries use strings.ToLower(strings.TrimSpace(value)), matching the
// built-in checker. There is no Unicode normalization or full case folding.
// Invalid UTF-8 entries, entries empty after trimming, and nil options return a
// nil checker and an error that never contains the entry text. Duplicates are
// accepted. Invalid UTF-8 queries never match.
//
// A nil or empty passwords slice is valid and blocks nothing unless
// WithBuiltInCommonPasswords is supplied. Assigning the result to
// PasswordPolicy.Blocklist replaces that policy's checker; built-ins are not
// included implicitly. Construction does not change any existing policy.
// Checks are synchronous and perform no I/O; the existing bool-only interface
// has no context or operational-error contract.
func NewLocalCommonPasswordChecker(
	passwords []string,
	options ...LocalCommonPasswordCheckerOption,
) (CommonPasswordChecker, error) {
	var config localCommonPasswordCheckerConfig
	for index, option := range options {
		if option == nil {
			return nil, fmt.Errorf("local common password checker: option %d is nil", index)
		}
		option(&config)
	}

	dictionary := make(localCommonPasswordChecker, len(passwords))
	for index, password := range passwords {
		if !utf8.ValidString(password) {
			return nil, fmt.Errorf("local common password checker: entry %d is not valid UTF-8", index)
		}
		normalized := strings.ToLower(strings.TrimSpace(password))
		if normalized == "" {
			return nil, fmt.Errorf("local common password checker: entry %d is empty after trimming", index)
		}
		dictionary[normalized] = struct{}{}
	}
	if config.includeBuiltIns {
		for password := range builtInCommonPasswords {
			dictionary[password] = struct{}{}
		}
	}

	return dictionary, nil
}

type localCommonPasswordChecker map[string]struct{}

func (c localCommonPasswordChecker) IsCommonPassword(password string) bool {
	if !utf8.ValidString(password) {
		return false
	}
	_, found := c[strings.ToLower(strings.TrimSpace(password))]
	return found
}
