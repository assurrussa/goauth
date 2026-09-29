package goauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	DefaultPasswordMinLength           = 8
	DefaultPasswordMaxLength           = 128
	DefaultArgon2MemoryKiB             = 19 * 1024
	DefaultArgon2Iterations            = 2
	DefaultArgon2Parallelism           = 1
	DefaultMaxConcurrentPasswordHashes = 4
)

type PasswordHasher interface {
	HashPassword(password string) (string, error)
	// VerifyPassword returns nil on a match and an error on a mismatch. Runtime
	// preserves native mismatch errors as invalid credentials. Operational errors
	// must wrap ErrPasswordVerificationUnavailable, ErrPasswordHashOverloaded,
	// context.Canceled or context.DeadlineExceeded instead.
	VerifyPassword(phc, password string) error
}

func isPasswordVerificationFailure(err error) bool {
	return errors.Is(err, ErrPasswordVerificationUnavailable) || errors.Is(err, ErrPasswordHashOverloaded) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

type Argon2idConfig struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
	Random      io.Reader
}

type Argon2idHasher struct {
	config Argon2idConfig
}

func NewArgon2idHasher(config Argon2idConfig) (*Argon2idHasher, error) {
	if config.MemoryKiB == 0 {
		config.MemoryKiB = DefaultArgon2MemoryKiB
	}
	if config.Iterations == 0 {
		config.Iterations = DefaultArgon2Iterations
	}
	if config.Parallelism == 0 {
		config.Parallelism = DefaultArgon2Parallelism
	}
	if config.SaltLength == 0 {
		config.SaltLength = 16
	}
	if config.KeyLength == 0 {
		config.KeyLength = 32
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.MemoryKiB < DefaultArgon2MemoryKiB || config.Iterations < DefaultArgon2Iterations || config.Parallelism < 1 {
		return nil, errors.New("argon2id parameters are below the goauth minimum")
	}
	if config.MemoryKiB > 1024*1024 || config.Iterations > 10 || config.Parallelism > 16 {
		return nil, errors.New("argon2id parameters exceed the goauth safety limit")
	}
	if config.SaltLength < 16 || config.SaltLength > 64 || config.KeyLength < 32 || config.KeyLength > 64 {
		return nil, errors.New("invalid argon2id salt or key length")
	}

	return &Argon2idHasher{config: config}, nil
}

func (h *Argon2idHasher) HashPassword(password string) (string, error) {
	if h == nil {
		return "", errors.New("argon2id hasher is nil")
	}
	if !validPasswordInput(password) {
		return "", ErrInvalidPassword
	}
	salt := make([]byte, h.config.SaltLength)
	if _, err := io.ReadFull(h.config.Random, salt); err != nil {
		return "", fmt.Errorf("generate argon2id salt: %w", err)
	}
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		h.config.Iterations,
		h.config.MemoryKiB,
		h.config.Parallelism,
		h.config.KeyLength,
	)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.config.MemoryKiB,
		h.config.Iterations,
		h.config.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func (h *Argon2idHasher) VerifyPassword(phc, password string) error {
	if !validPasswordInput(password) {
		return ErrInvalidCredentials
	}
	params, salt, expected, err := parseArgon2idPHC(phc)
	if err != nil {
		return ErrInvalidCredentials
	}
	actual := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.MemoryKiB,
		params.Parallelism,
		uint32(len(expected)),
	)
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return ErrInvalidCredentials
	}

	return nil
}

func parseArgon2idPHC(phc string) (config Argon2idConfig, salt, hash []byte, err error) {
	if len(phc) > 512 {
		return Argon2idConfig{}, nil, nil, errors.New("invalid argon2id PHC length")
	}
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return Argon2idConfig{}, nil, nil, errors.New("invalid argon2id PHC")
	}
	parameters := strings.Split(parts[3], ",")
	if len(parameters) != 3 {
		return Argon2idConfig{}, nil, nil, errors.New("invalid argon2id parameters")
	}
	values := make(map[string]uint64, len(parameters))
	for _, parameter := range parameters {
		key, value, ok := strings.Cut(parameter, "=")
		if !ok {
			return Argon2idConfig{}, nil, nil, errors.New("invalid argon2id parameter")
		}
		if _, duplicate := values[key]; duplicate || (key != "m" && key != "t" && key != "p") {
			return Argon2idConfig{}, nil, nil, errors.New("invalid argon2id parameter key")
		}
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return Argon2idConfig{}, nil, nil, errors.New("invalid argon2id parameter")
		}
		values[key] = parsed
	}
	// Check before narrowing: e.g. p=257 must not wrap to one lane.
	if values["m"] < DefaultArgon2MemoryKiB || values["m"] > 1024*1024 ||
		values["t"] < DefaultArgon2Iterations || values["t"] > 10 ||
		values["p"] < 1 || values["p"] > 16 {
		return Argon2idConfig{}, nil, nil, errors.New("unsafe argon2id parameters")
	}
	config = Argon2idConfig{MemoryKiB: uint32(values["m"]), Iterations: uint32(values["t"]), Parallelism: uint8(values["p"])}
	if len(parts[4]) > base64.RawStdEncoding.EncodedLen(64) || len(parts[5]) > base64.RawStdEncoding.EncodedLen(64) {
		return Argon2idConfig{}, nil, nil, errors.New("invalid argon2id encoded length")
	}
	salt, err = base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return Argon2idConfig{}, nil, nil, errors.New("invalid argon2id salt")
	}
	hash, err = base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(hash) < 32 || len(hash) > 64 {
		return Argon2idConfig{}, nil, nil, errors.New("invalid argon2id hash")
	}

	return config, salt, hash, nil
}

type CommonPasswordChecker interface {
	IsCommonPassword(password string) bool
}

type CommonPasswordCheckerFunc func(string) bool

func (f CommonPasswordCheckerFunc) IsCommonPassword(password string) bool {
	return f(password)
}

type PasswordPolicy struct {
	MinLength        int
	MaxLength        int
	Blocklist        CommonPasswordChecker
	DisableBlocklist bool
}

func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength: DefaultPasswordMinLength,
		MaxLength: DefaultPasswordMaxLength,
		Blocklist: CommonPasswordCheckerFunc(func(password string) bool {
			_, found := builtInCommonPasswords[strings.ToLower(strings.TrimSpace(password))]
			return found
		}),
	}
}

func (p PasswordPolicy) Validate(password string) error {
	if !validPasswordInput(password) {
		return ErrInvalidPassword
	}
	if p.Blocklist == nil && !p.DisableBlocklist {
		p.Blocklist = DefaultPasswordPolicy().Blocklist
	}
	if p.MinLength == 0 {
		p.MinLength = DefaultPasswordMinLength
	}
	if p.MaxLength == 0 {
		p.MaxLength = DefaultPasswordMaxLength
	}
	if p.MinLength < DefaultPasswordMinLength || p.MaxLength > DefaultPasswordMaxLength || p.MinLength > p.MaxLength {
		return ErrInvalidPassword
	}
	if !utf8.ValidString(password) {
		return ErrInvalidPassword
	}
	length := utf8.RuneCountInString(password)
	if length < p.MinLength || length > p.MaxLength {
		return ErrInvalidPassword
	}
	if !p.DisableBlocklist && p.Blocklist != nil && p.Blocklist.IsCommonPassword(password) {
		return ErrCommonPassword
	}

	return nil
}

// Input bounds apply to existing passwords as well as new ones. Minimum length
// and the blocklist are issuance policy and are deliberately absent here.
func validPasswordInput(password string) bool {
	return len(password) <= DefaultPasswordMaxLength*utf8.UTFMax && utf8.ValidString(password) &&
		utf8.RuneCountInString(password) <= DefaultPasswordMaxLength
}

// Each Runtime shares one budget across every hash and verification. Admission
// is immediate, so distinct identifiers cannot create an unbounded work queue.
type boundedPasswordHasher struct {
	delegate PasswordHasher
	active   chan struct{}
}

func (h *boundedPasswordHasher) HashPassword(password string) (string, error) {
	if !validPasswordInput(password) {
		return "", ErrInvalidPassword
	}
	select {
	case h.active <- struct{}{}:
		defer func() { <-h.active }()
		return h.delegate.HashPassword(password)
	default:
		return "", ErrPasswordHashOverloaded
	}
}

func (h *boundedPasswordHasher) VerifyPassword(phc, password string) error {
	if !validPasswordInput(password) {
		return ErrInvalidCredentials
	}
	select {
	case h.active <- struct{}{}:
		defer func() { <-h.active }()
		return h.delegate.VerifyPassword(phc, password)
	default:
		return ErrPasswordHashOverloaded
	}
}

var builtInCommonPasswords = map[string]struct{}{
	"12345678": {}, "123456789": {}, "1234567890": {}, "abcdefgh": {},
	"admin123": {}, "iloveyou": {}, "letmein123": {}, "password": {},
	"password1": {}, "password123": {}, "qwerty123": {}, "welcome1": {},
}
