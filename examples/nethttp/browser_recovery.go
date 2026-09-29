package main

import (
	"encoding/json"
	"net/http"
)

// forgetSession only removes this host's cookies. It does not authenticate,
// rotate, or revoke anything, even when the database is unavailable. Mount it
// behind the same CrossOriginProtection as all other browser mutations.
func (h host) forgetSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("X-Goauth-CSRF") != "1" {
		http.Error(w, "CSRF header required", http.StatusForbidden)
		return
	}
	h.clear(w)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]bool{
		"browserCredentialsCleared": true,
		"serverSessionsRevoked":     false,
	}); err != nil {
		return
	}
}
