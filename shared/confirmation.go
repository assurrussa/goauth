package shared

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	ErrInvalidCodeType            = errors.New("invalid code type")
	ErrInvalidConfirmationPurpose = errors.New("invalid purpose")
)

type ConfirmationType int16

const (
	ConfirmationTypeUnknown ConfirmationType = 0
	ConfirmationTypeEmail   ConfirmationType = 1
	ConfirmationTypePhone   ConfirmationType = 2
	ConfirmationTypeTgBot   ConfirmationType = 3
)

type ConfirmationAction int

const (
	ConfirmationActionSend ConfirmationAction = iota + 1
	ConfirmationActionVerify
)

func (t ConfirmationType) Parse(val string) ConfirmationType {
	switch val {
	case "email":
		return ConfirmationTypeEmail
	case "phone":
		return ConfirmationTypePhone
	case "tgbot":
		return ConfirmationTypeTgBot
	default:
		return ConfirmationTypeUnknown
	}
}

func (t ConfirmationType) ValidateFor(action ConfirmationAction) error {
	switch action {
	case ConfirmationActionSend:
		switch t {
		case ConfirmationTypeEmail, ConfirmationTypeTgBot:
			return nil
		default:
			return fmt.Errorf("invalid %w for send: %d, %s", ErrInvalidCodeType, t, t.ToString())
		}
	case ConfirmationActionVerify:
		switch t {
		case ConfirmationTypeEmail, ConfirmationTypePhone:
			return nil
		default:
			return fmt.Errorf("invalid %w for verify: %d, %s", ErrInvalidCodeType, t, t.ToString())
		}
	default:
		return fmt.Errorf("invalid action: %d", action)
	}
}

func (t ConfirmationType) String() string {
	return strconv.Itoa(int(t))
}

func (t ConfirmationType) ToString() string {
	switch t {
	case ConfirmationTypeEmail:
		return "email"
	case ConfirmationTypePhone:
		return "phone"
	case ConfirmationTypeTgBot:
		return "tgbot"
	default:
		return "unknown"
	}
}

type ConfirmationPurpose int16

const (
	ConfirmationPurposeUnknown      ConfirmationPurpose = 0
	ConfirmationPurposeConfirmation ConfirmationPurpose = 1
)

func (p ConfirmationPurpose) String() string {
	return strconv.Itoa(int(p))
}

func (p ConfirmationPurpose) ToString() string {
	switch p {
	case ConfirmationPurposeConfirmation:
		return "confirmation"
	default:
		return "unknown"
	}
}

func (p ConfirmationPurpose) Validate() error {
	if p == ConfirmationPurposeConfirmation {
		return nil
	}

	return fmt.Errorf("invalid %w: %d, %s", ErrInvalidConfirmationPurpose, p, p.ToString())
}

type ConfirmCode string

func (c ConfirmCode) String() string {
	return string(c)
}

func ConfirmCodeNormalize(code ConfirmCode) ConfirmCode {
	var result strings.Builder
	for _, r := range string(code) {
		if r != ' ' && r != '\t' && r != '\n' && r != '\r' {
			_, _ = result.WriteRune(r)
		}
	}

	return ConfirmCode(result.String())
}
