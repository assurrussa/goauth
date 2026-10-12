package goauth_test

import (
	"errors"
	"testing"
	"time"

	"github.com/assurrussa/goauth"
)

func TestMFALoginPendingBoundaries(t *testing.T) {
	id, err := goauth.NewMFALoginID()
	if err != nil {
		t.Fatal(err)
	}
	subject := goauth.NewSubjectID()
	now := time.Unix(1800, 0)
	account := goauth.Account{Subject: goauth.Subject{ID: subject, Status: goauth.SubjectStatusActive, SecurityVersion: 3}}
	factor := goauth.MFAFactorRecord{ID: "pending-factor", Revision: 2, Enabled: true}
	binding := [32]byte{1}
	original := goauth.MFALoginPending{
		ID: id, SubjectID: subject, Realm: goauth.RealmAdmin, SecurityVersion: 3, FactorID: "pending-factor", FactorRevision: 2,
		BindingDigest: binding, AuthenticatedAt: now, ExpiresAt: now.Add(goauth.MFALoginLifetime),
	}
	if err := goauth.ValidateMFALoginPending(original, account, factor, goauth.RealmAdmin, binding, now); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*goauth.MFALoginPending){
		"enrollment purpose":    func(p *goauth.MFALoginPending) { p.Kind = goauth.MFALoginKindEnrollment },
		"unknown purpose":       func(p *goauth.MFALoginPending) { p.Kind = "unknown" },
		testSubjectMutation:     func(p *goauth.MFALoginPending) { p.SubjectID = goauth.NewSubjectID() },
		"realm":                 func(p *goauth.MFALoginPending) { p.Realm = goauth.RealmUser },
		"security version":      func(p *goauth.MFALoginPending) { p.SecurityVersion++ },
		"factor binding":        func(p *goauth.MFALoginPending) { p.FactorID = "replacement" },
		"revision":              func(p *goauth.MFALoginPending) { p.FactorRevision++ },
		"binding":               func(p *goauth.MFALoginPending) { p.BindingDigest[0]++ },
		"expiry":                func(p *goauth.MFALoginPending) { p.ExpiresAt = now },
		"future authentication": func(p *goauth.MFALoginPending) { p.AuthenticatedAt = now.Add(time.Second) },
		"extended lifetime":     func(p *goauth.MFALoginPending) { p.ExpiresAt = now.Add(goauth.MFALoginLifetime + time.Nanosecond) },
		"identifier":            func(p *goauth.MFALoginPending) { p.ID = "client-selected" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			pending := original
			mutate(&pending)
			if !errors.Is(goauth.ValidateMFALoginPending(pending, account, factor, goauth.RealmAdmin, binding, now),
				goauth.ErrMFALoginDenied) {
				t.Fatal("accepted stale/unbound continuation")
			}
		})
	}
	if goauth.ValidateMFALoginPending(original, account, factor, goauth.RealmAdmin, binding, original.ExpiresAt) == nil {
		t.Fatal("accepted at expiry")
	}
	factor.Enabled = false
	if goauth.ValidateMFALoginPending(original, account, factor, goauth.RealmAdmin, binding, now) == nil {
		t.Fatal("accepted disabled factor")
	}
	factor.Enabled = true
	account.Subject.Status = goauth.SubjectStatusSuspended
	if goauth.ValidateMFALoginPending(original, account, factor, goauth.RealmAdmin, binding, now) == nil {
		t.Fatal("accepted suspended subject")
	}
}
