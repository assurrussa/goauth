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

func (h *boundedPasswordHasher) verifyCredential(phc, password string, policy PasswordInputPolicy) error {
	switch policy {
	case "", PasswordInputPolicyUnicode:
		return h.VerifyPassword(phc, password)
	case PasswordInputPolicyLegacyBytes256:
		if !h.supportsImport() {
			return ErrPasswordVerificationUnavailable
		}
		if len(password) > 256 || validateImportedCredential(phc, policy) != nil {
			return ErrInvalidCredentials
		}
		select {
		case h.active <- struct{}{}:
			defer func() { <-h.active }()
			return verifyArgon2idPassword(phc, password)
		default:
			return ErrPasswordHashOverloaded
		}
	default:
		return ErrInvalidCredentials
	}
}
