package goauth

import (
	"context"
	"fmt"
	"strings"
	"unicode"
)

func NormalizeEmail(value string) (string, error) {
	display := strings.TrimSpace(value)
	if display == "" || len(display) > 254 || strings.Count(display, "@") != 1 {
		return "", ErrInvalidIdentifier
	}
	local, domain, ok := strings.Cut(display, "@")
	if !ok || local == "" || domain == "" || len(local) > 64 {
		return "", ErrInvalidIdentifier
	}
	for _, r := range display {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", ErrInvalidIdentifier
		}
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
		return "", ErrInvalidIdentifier
	}

	return strings.ToLower(display), nil
}

type emailIdentifierResolver struct{}

func (emailIdentifierResolver) NormalizeIdentifier(_ context.Context, input IdentifierInput) (IdentifierInput, error) {
	normalized, err := NormalizeEmail(input.Value)
	if err != nil {
		return IdentifierInput{}, fmt.Errorf("normalize email: %w", err)
	}

	return IdentifierInput{Scheme: IdentifierSchemeEmail, Value: normalized}, nil
}
