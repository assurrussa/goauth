package goauth

import "io"

// This public, non-secret string is used only for dummy verification work.
//
//nolint:gosec // Synthetic input for dummy work, not an installed credential.
const compatibilityDummyPassword = "goauth-compatibility-dummy-password"

// Both jobs stay inside one Runtime hash slot and execute sequentially.
// Capacity must include both allocations plus runtime/GC headroom; sequential
// execution does not promise reclamation of the first allocation before the next.
type legacyPasswordCompatibility struct {
	currentProfile  Argon2idConfig
	currentDummyPHC string
	legacyDummyPHC  string
}

type (
	passwordVerificationWork struct{ phc, password string }
	passwordVerificationPlan struct {
		work     [2]passwordVerificationWork
		selected int // -1 always denies, even if either dummy verification matches.
	}
)

func legacyPasswordProfile() Argon2idConfig {
	return Argon2idConfig{MemoryKiB: 65536, Iterations: 3, Parallelism: 1, SaltLength: 16, KeyLength: 32}
}

func (h *boundedPasswordHasher) enableLegacyCompatibility(random io.Reader) error {
	current, ok := h.delegate.(*Argon2idHasher)
	if !ok {
		return ErrLocalIdentityUnsupported
	}
	profile := legacyPasswordProfile()
	profile.Random = random
	legacy, err := NewArgon2idHasher(profile)
	if err != nil {
		return err
	}
	// Construction uses the same admission channel too; no independent budget.
	boundedLegacy := &boundedPasswordHasher{delegate: legacy, active: h.active}
	dummy, err := boundedLegacy.HashPassword(compatibilityDummyPassword)
	if err != nil {
		return err
	}
	h.compatibility = &legacyPasswordCompatibility{
		currentProfile: current.config, currentDummyPHC: h.dummyPHC, legacyDummyPHC: dummy,
	}
	return nil
}

func matchesPasswordProfile(phc string, profile Argon2idConfig) bool {
	actual, salt, digest, err := parseArgon2idPHC(phc)
	return err == nil && actual.MemoryKiB == profile.MemoryKiB && actual.Iterations == profile.Iterations &&
		actual.Parallelism == profile.Parallelism && uint32(len(salt)) == profile.SaltLength && uint32(len(digest)) == profile.KeyLength
}

func (c *legacyPasswordCompatibility) plan(phc, password string, policy PasswordInputPolicy) passwordVerificationPlan {
	// The caller has bounded the input to the union of supported policies. Both
	// dummy jobs use the same original bytes too; only real-slot selection below
	// decides whether the persisted policy permits authentication with those bytes.
	plan := passwordVerificationPlan{selected: -1, work: [2]passwordVerificationWork{
		{phc: c.currentDummyPHC, password: password}, {phc: c.legacyDummyPHC, password: password},
	}}
	switch policy {
	case "", PasswordInputPolicyUnicode:
		if !validPasswordInput(password) {
			return plan
		}
		switch {
		case matchesPasswordProfile(phc, c.currentProfile):
			plan.selected = 0
		case matchesPasswordProfile(phc, legacyPasswordProfile()):
			plan.selected = 1
		}
	case PasswordInputPolicyLegacyBytes256:
		if len(password) <= 256 && validateImportedCredential(phc, policy) == nil {
			plan.selected = 1
		}
	}
	if plan.selected >= 0 {
		plan.work[plan.selected] = passwordVerificationWork{phc: phc, password: password}
	}
	return plan
}

func (h *boundedPasswordHasher) verifyPlan(plan passwordVerificationPlan, verify func(string, string) error) error {
	select {
	case h.active <- struct{}{}:
		defer func() { <-h.active }()
	default:
		return ErrPasswordHashOverloaded
	}
	var outcomes [2]error
	for index, work := range plan.work {
		outcomes[index] = verify(work.phc, work.password)
	}
	for _, err := range outcomes {
		if isPasswordVerificationFailure(err) {
			return err
		}
	}
	if plan.selected < 0 {
		return ErrInvalidCredentials
	}
	return outcomes[plan.selected]
}
