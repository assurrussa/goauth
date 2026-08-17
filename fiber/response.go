package fiber

import (
	"time"

	"github.com/assurrussa/goauth"
)

type registerResponse struct {
	Account accountResponse `json:"account"`
	Tokens  tokenResponse   `json:"tokens"`
}

type loginResponse struct {
	Account accountResponse `json:"account"`
	Tokens  tokenResponse   `json:"tokens"`
}

type accountResponse struct {
	SubjectID     string               `json:"subjectId"`
	Status        goauth.SubjectStatus `json:"status"`
	Email         string               `json:"email"`
	EmailVerified bool                 `json:"emailVerified"`
	Profile       goauth.BasicProfile  `json:"profile"`
}

type tokenResponse struct {
	AccessToken      string              `json:"accessToken"`
	RefreshToken     string              `json:"refreshToken"`
	AccessExpiresAt  time.Time           `json:"accessExpiresAt"`
	RefreshExpiresAt time.Time           `json:"refreshExpiresAt"`
	Realm            goauth.Realm        `json:"realm"`
	Scope            goauth.SessionScope `json:"scope"`
}

func accountResponseFrom(account goauth.Account) accountResponse {
	return accountResponse{
		SubjectID:     account.Subject.ID.String(),
		Status:        account.Subject.Status,
		Email:         account.PrimaryEmail.DisplayValue,
		EmailVerified: account.EmailVerified(),
		Profile:       account.Profile,
	}
}

func tokenResponseFrom(pair goauth.TokenPair) tokenResponse {
	return tokenResponse{
		AccessToken:      pair.AccessToken,
		RefreshToken:     pair.RefreshToken,
		AccessExpiresAt:  pair.AccessExpiresAt,
		RefreshExpiresAt: pair.RefreshExpiresAt,
		Realm:            pair.Session.Realm,
		Scope:            pair.Session.Scope,
	}
}
