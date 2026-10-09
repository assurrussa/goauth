# Opt-in local common-password dictionaries

The default password policy is unchanged: 8–128 Unicode code points and the
existing twelve built-in common passwords. `PasswordPolicy{}` and partial
policies still select that default checker when `Blocklist` is nil and
`DisableBlocklist` is false. Existing checker interfaces, login, hashing,
credential verification, and stored credentials are unchanged.

Hosts can prepare a dictionary in memory and inject it through the existing
`PasswordPolicy.Blocklist` field. No service, corpus, download, database,
migration, runtime setting, or dependency is introduced.

## Add host words while retaining the built-ins

```go
checker, err := goauth.NewLocalCommonPasswordChecker(
    []string{"Tenant-Example-Passphrase", "Another-Example-Passphrase"},
    goauth.WithBuiltInCommonPasswords(),
)
if err != nil {
    return err
}

config.PasswordPolicy = goauth.PasswordPolicy{Blocklist: checker}
// Use config with the existing goauth.NewRuntime assembly.
```

These are synthetic example dictionary entries, not credentials. The host owns
selection, provenance, licensing, size, and loading of its dictionary. Do not
populate a dictionary with real user passwords. The helper is a lookup set,
not a breached-password corpus or a password-strength estimator.

The constructor returns the existing `CommonPasswordChecker` interface.
Its implementation and map are private. The only typed functional option,
`WithBuiltInCommonPasswords()`, unions a copy of the existing built-in entries
into this checker; repeating it is harmless. Neither dictionary construction
nor later lookups mutate the built-in map or any other checker.

## Replacement and empty-set semantics

- Without the option, the checker contains only the supplied entries.
- A nil or empty entry slice is valid. Without the option it matches nothing;
  assigning it to `PasswordPolicy.Blocklist` intentionally replaces the default
  dictionary with an empty one. It does not disable length or UTF-8 validation.
- An empty slice with `WithBuiltInCommonPasswords()` selects only the built-ins.
- A nil `Blocklist` still means the pre-existing default behavior. It differs
  from a successfully constructed empty checker.
- `DisableBlocklist: true` still skips whichever checker is configured.
- To replace a running host's dictionary, construct a new checker and use the
  host's existing safe Runtime/configuration lifecycle. This API adds no mutable
  dictionary, reload mechanism, or synchronization for host configuration writes.

## Matching, validation, and concurrency

Entries and valid UTF-8 queries are matched using exactly
`strings.ToLower(strings.TrimSpace(value))`, as the built-in checker does.
Leading/trailing Unicode whitespace and case are ignored for this lookup only.
Passwords passed to hashing and verification are never rewritten by the helper.
There is no NFC/NFKC normalization, accent removal, substring matching, or full
Unicode case folding: `CAFÉ` matches `café`, decomposed `cafe\u0301` does not;
`Straße` does not match `STRASSE`.

Construction rejects nil options, invalid UTF-8 entries, and entries empty after
trimming. Failure returns a nil checker and an error naming the zero-based
option or entry index, never the entry text. Duplicate normalized entries are
accepted and deduplicated. Entries are not subject to issuance length limits;
those limits remain the responsibility of `PasswordPolicy.Validate`.

The caller must not mutate the input slices while construction is running.
After success, changing either input slice cannot change the checker. The
private dictionary is read-only, so a checker can be shared by concurrent
validation calls without locks.

The existing `IsCommonPassword(string) bool` method is synchronous, performs no
I/O, and has no context, cancellation, or operational-error return. Invalid UTF-8
queries return false; this means no dictionary match, not password acceptance.
`PasswordPolicy.Validate` still rejects malformed or out-of-bounds input before
calling the checker. Only construction can return a configuration error.

## Compatibility and verification

The helper affects new-password issuance only when explicitly injected.
Existing credentials remain usable through normal login even if a newly
configured dictionary contains their password. Nothing in this change raises
the minimum length, adds character-composition rules, expands the default twelve
entries, or silently changes a host's policy.

Public-surface compilation covers the constructor and typed option.
The runnable clean-consumer probe injects the checker into a test Runtime;
regression tests cover copying, Unicode and whitespace rules, duplicates,
empty sets, invalid configuration, parallel reads, default isolation, and
login compatibility.
