package goauth

import (
	"encoding/base64"
	"fmt"
)

func validateImportedCredential(phc string, policy PasswordInputPolicy) error {
	config, salt, digest, err := parseArgon2idPHC(phc)
	if err != nil {
		return ErrInvalidPassword
	}
	canonical := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", config.MemoryKiB,
		config.Iterations, config.Parallelism, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(digest))
	if phc != canonical {
		return ErrInvalidPassword
	}
	switch policy {
	case PasswordInputPolicyUnicode:
		return nil
	case PasswordInputPolicyLegacyBytes256:
		if config.MemoryKiB == 65536 && config.Iterations == 3 && config.Parallelism == 1 && len(salt) == 16 && len(digest) == 32 {
			return nil
		}
	}
	return ErrInvalidPassword
}

func (h *boundedPasswordHasher) supportsImport() bool {
	_, ok := h.delegate.(*Argon2idHasher)
	return ok
}

func (h *boundedPasswordHasher) validateImport(phc string, policy PasswordInputPolicy) error {
	if policy == PasswordInputPolicyLegacyBytes256 && h.compatibility == nil {
		return ErrLocalIdentityUnsupported
	}
	if err := validateImportedCredential(phc, policy); err != nil {
		return err
	}
	current, ok := h.delegate.(*Argon2idHasher)
	if !ok {
		return ErrLocalIdentityUnsupported
	}
	if !matchesPasswordProfile(phc, current.config) &&
		(h.compatibility == nil || !matchesPasswordProfile(phc, legacyPasswordProfile())) {
		return ErrInvalidPassword
	}
	return nil
}

func (h *boundedPasswordHasher) verifyCredential(phc, password string, policy PasswordInputPolicy) error {
	if h.compatibility != nil {
		if !validPasswordInput(password) && len(password) > 256 {
			return ErrInvalidCredentials
		}
		return h.verifyPlan(h.compatibility.plan(phc, password, policy), verifyArgon2idPassword)
	}
	if (policy == "" || policy == PasswordInputPolicyUnicode) && phc != "" {
		return h.VerifyPassword(phc, password)
	}
	// A missing or unsupported credential must not become valid when its dummy
	// happens to match. Default-off mode never passes legacy bytes to a verifier.
	if err := h.VerifyPassword(h.dummyPHC, password); isPasswordVerificationFailure(err) {
		return err
	}
	return ErrInvalidCredentials
}
