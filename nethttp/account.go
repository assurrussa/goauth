package nethttp

import (
	"net/http"

	"github.com/assurrussa/goauth"
)

func (a *Adapter) Logout(w http.ResponseWriter, r *http.Request) {
	auth, ok := AuthContext(r.Context())
	if !ok {
		WriteError(w, goauth.ErrInvalidToken)
		return
	}
	if err := a.runtime.Logout(r.Context(), auth.SubjectID, auth.SessionID); err != nil {
		WriteError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Adapter) LogoutAll(w http.ResponseWriter, r *http.Request) {
	auth, ok := AuthContext(r.Context())
	if !ok {
		WriteError(w, goauth.ErrInvalidToken)
		return
	}
	if _, err := a.runtime.LogoutAll(r.Context(), auth.SubjectID); err != nil {
		WriteError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Adapter) ChangePassword(w http.ResponseWriter, r *http.Request) {
	auth, ok := AuthContext(r.Context())
	if !ok {
		WriteError(w, goauth.ErrInvalidToken)
		return
	}
	var request struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := decode(w, r, &request); err != nil {
		WriteError(w, goauth.ErrInvalidPassword)
		return
	}
	account, err := a.runtime.ChangePassword(r.Context(), goauth.ChangePasswordRequest{
		SubjectID:       auth.SubjectID,
		CurrentPassword: request.CurrentPassword,
		NewPassword:     request.NewPassword,
	})
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, accountResponseFrom(account))
}

func (a *Adapter) RequestEmailChange(w http.ResponseWriter, r *http.Request) {
	auth, ok := AuthContext(r.Context())
	if !ok {
		WriteError(w, goauth.ErrInvalidToken)
		return
	}
	var request struct {
		Email string `json:"email"`
	}
	if err := decode(w, r, &request); err != nil {
		WriteError(w, goauth.ErrInvalidIdentifier)
		return
	}
	if err := a.runtime.RequestEmailChange(r.Context(), auth.SubjectID, request.Email); err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

func (a *Adapter) ConfirmEmailChange(w http.ResponseWriter, r *http.Request) {
	auth, ok := AuthContext(r.Context())
	if !ok {
		WriteError(w, goauth.ErrInvalidToken)
		return
	}
	var request struct {
		Code string `json:"code"`
	}
	if err := decode(w, r, &request); err != nil {
		WriteError(w, goauth.ErrInvalidConfirmationCode)
		return
	}
	account, err := a.runtime.ConfirmEmailChange(r.Context(), auth.SubjectID, request.Code)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, accountResponseFrom(account))
}
