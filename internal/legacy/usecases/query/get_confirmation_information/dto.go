package getconfirmationinformation

import (
	authcore "github.com/assurrussa/goauth/internal/legacy/core"
)

// Query for getting confirmation information

type Query struct {
	SubjectID authcore.SubjectID
}

// Result of getting confirmation information

type Result struct {
	Email            string
	Phone            string
	IsEmailConfirmed bool
	IsPhoneConfirmed bool
}
