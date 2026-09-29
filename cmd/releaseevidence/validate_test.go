package main

import (
	"fmt"
	"strings"
	"testing"
)

const fixtureTag = "v0.5.0"

const reviewedSHA = "0123456789abcdef0123456789abcdef01234567"

const findingOpen = "open"

func passingEvidence() map[string]any {
	scenarios := make([]any, 0, len(requiredCases()))
	for id := range requiredCases() {
		requirements := make([]any, 0, 10)
		for i := 1; i <= 10; i++ {
			requirements = append(requirements, fmt.Sprintf("AUTH-%02d", i))
		}
		scenarios = append(scenarios, map[string]any{
			"id": id, "source_sha": reviewedSHA, fieldReleaseBlocking: true, fieldOutcome: outcomePass,
			"requirement_ids": requirements, "preconditions": []any{"isolated fixture"}, "action": "exercise case",
			fieldCommand: "verified command", fieldEvidence: "private evidence reference", fieldReviewer: fieldReviewer,
			"http_core_outcome":        map[string]any{"expected": "deny", "observed": "deny"},
			"durable_state_assertions": []any{"no forbidden writes"}, "security_event_observations": []any{"expected events"},
		})
	}
	gates := map[string]any{}
	for _, name := range releaseGateNames {
		gates[name] = map[string]any{fieldStatus: outcomePass, "evidence": "private evidence reference"}
	}
	object(gates["candidate"])["source_sha"] = reviewedSHA
	object(gates["candidate"])[fieldCommand] = "make release-candidate-readiness"
	object(gates["anonymous_exact_tag"])["tag"] = fixtureTag
	profiles := map[string]any{}
	for _, id := range []string{"P1", "P2", "P3", "P4"} {
		profiles[id] = map[string]any{fieldStatus: outcomePass, "evidence": "private evidence"}
	}
	hosts := map[string]any{}
	for _, name := range []string{hostSite, hostAdmin} {
		hosts[name] = map[string]any{
			fieldOutcome: outcomePass, fieldHostSHA: reviewedSHA, fieldResolvedVersion: fixtureTag,
			fieldResolvedSHA: reviewedSHA, fieldReplacement: false,
			fieldCommand: "host acceptance", fieldEvidence: "private host evidence",
		}
	}
	return map[string]any{
		"spec_version": 1, "candidate": map[string]any{"sha": reviewedSHA, "tag": fixtureTag, "toolchain": "go1.27.1"},
		"host_checks": hosts, "scenarios": scenarios, "profiles": profiles, "release_gates": gates, "findings": []any{},
		"owner_approval": map[string]any{
			"release_claim": "public preview", "approved_by": "owner",
			"approved_on": "2026-09-29", "support_scope": "documented profiles",
		},
	}
}

func TestValidEvidence(t *testing.T) {
	if err := validate(passingEvidence(), reviewedSHA); err != nil {
		t.Fatal(err)
	}
}

func TestFindingRequiresExplicitBoolean(t *testing.T) {
	cases := []struct {
		name    string
		finding map[string]any
		valid   bool
	}{
		{"missing", map[string]any{fieldStatus: findingResolved}, false},
		{"null", map[string]any{fieldReleaseBlocking: nil, fieldStatus: findingResolved}, false},
		{"string true", map[string]any{fieldReleaseBlocking: "true", fieldStatus: findingResolved}, false},
		{"string false", map[string]any{fieldReleaseBlocking: "false", fieldStatus: findingResolved}, false},
		{"number one", map[string]any{fieldReleaseBlocking: 1, fieldStatus: findingResolved}, false},
		{"number zero", map[string]any{fieldReleaseBlocking: 0, fieldStatus: findingResolved}, false},
		{"nonblocking open", map[string]any{fieldReleaseBlocking: false, fieldStatus: findingOpen}, true},
		{"blocking resolved", map[string]any{fieldReleaseBlocking: true, fieldStatus: findingResolved}, true},
		{"blocking open", map[string]any{fieldReleaseBlocking: true, fieldStatus: findingOpen}, false},
		{"blocking without status", map[string]any{fieldReleaseBlocking: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := passingEvidence()
			d["findings"] = []any{tc.finding}
			if err := validate(d, reviewedSHA); (err == nil) != tc.valid {
				t.Fatalf("valid=%t, validation error: %v", tc.valid, err)
			}
		})
	}
}

func TestEvidenceRejectsIncompleteOrStaleClaims(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"stale SHA", func(d map[string]any) { object(d["candidate"])["sha"] = "wrong" }},
		{"not run", func(d map[string]any) { object(scenarioEntries(d)[0])[fieldOutcome] = "not_run" }},
		{"missing case", func(d map[string]any) { d["scenarios"] = scenarioEntries(d)[1:] }},
		{"duplicate", func(d map[string]any) { a := scenarioEntries(d); d["scenarios"] = append(a, a[0]) }},
		{"weakened blocking", func(d map[string]any) { object(scenarioEntries(d)[0])[fieldReleaseBlocking] = false }},
		{"missing observations", func(d map[string]any) { delete(object(scenarioEntries(d)[0]), "durable_state_assertions") }},
		{"unapproved exclusion", func(d map[string]any) { object(scenarioEntries(d)[0])[fieldOutcome] = outcomeExcluded }},
		{"runner blocked", func(d map[string]any) { object(object(d["release_gates"])["candidate"])[fieldStatus] = outcomeBlocked }},
		{"wrong tag", func(d map[string]any) { object(object(d["release_gates"])["anonymous_exact_tag"])["tag"] = "v0.4.1" }},
		{"open finding", func(d map[string]any) {
			d["findings"] = []any{map[string]any{fieldReleaseBlocking: true, fieldStatus: findingOpen}}
		}},
		{"no owner", func(d map[string]any) { delete(d, "owner_approval") }},
		{"historical summary", func(d map[string]any) { d["scenarios"] = map[string]any{"SEC-01": outcomePass} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := passingEvidence()
			tc.mutate(d)
			if validate(d, reviewedSHA) == nil {
				t.Fatal("invalid evidence accepted")
			}
		})
	}
}

func TestEvidenceExclusionCannotHideAdvertisedProfile(t *testing.T) {
	d := passingEvidence()
	for _, entry := range scenarioEntries(d) {
		s := object(entry)
		if strings.HasPrefix(text(s["id"]), "OID-") {
			s[fieldOutcome] = outcomeExcluded
			s["not_applicable_reason"] = "OIDC not advertised"
			s[fieldReviewer] = fieldReviewer
		}
	}
	if validate(d, reviewedSHA) == nil {
		t.Fatal("advertised profile exclusion accepted")
	}
	object(d["profiles"])["P4"] = map[string]any{
		fieldStatus: outcomeExcluded, "not_applicable_reason": "OIDC not advertised", fieldReviewer: fieldReviewer,
	}
	if err := validate(d, reviewedSHA); err != nil {
		t.Fatal(err)
	}
}

func scenarioEntries(d map[string]any) []any { entries, _ := d["scenarios"].([]any); return entries }

func TestHostEvidence(t *testing.T) {
	for _, name := range []string{hostSite, hostAdmin} {
		t.Run(name, func(t *testing.T) {
			for _, replacement := range []bool{false, true} {
				d := passingEvidence()
				object(object(d["host_checks"])[name])[fieldReplacement] = replacement
				if err := validate(d, reviewedSHA); err != nil {
					t.Fatalf("exact SHA with replacement %t: %v", replacement, err)
				}
			}
			tests := []struct {
				name  string
				field string
				value any
			}{
				{"not run", fieldOutcome, "not_run"},
				{"failed", fieldOutcome, "fail"},
				{outcomeBlocked, fieldOutcome, outcomeBlocked},
				{"stale", fieldResolvedSHA, strings.Repeat("f", 40)},
				{"short host SHA", fieldHostSHA, "0123456"},
				{"uppercase host SHA", fieldHostSHA, strings.Repeat("A", 40)},
				{"empty version", fieldResolvedVersion, " "},
				{"empty command", fieldCommand, " "},
				{"empty evidence", fieldEvidence, " "},
				{"replacement null", fieldReplacement, nil},
				{"replacement string", fieldReplacement, "false"},
			}
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					d := passingEvidence()
					object(object(d["host_checks"])[name])[tc.field] = tc.value
					if err := validate(d, reviewedSHA); err == nil || !strings.Contains(err.Error(), "host_checks."+name) {
						t.Fatalf("invalid host evidence accepted or misattributed: %v", err)
					}
				})
			}
			for _, field := range []string{
				fieldOutcome, fieldHostSHA, fieldResolvedVersion, fieldResolvedSHA,
				fieldReplacement, fieldCommand, fieldEvidence,
			} {
				d := passingEvidence()
				delete(object(object(d["host_checks"])[name]), field)
				if err := validate(d, reviewedSHA); err == nil {
					t.Fatalf("missing host field %s accepted", field)
				}
			}
			d := passingEvidence()
			delete(object(d["host_checks"]), name)
			if err := validate(d, reviewedSHA); err == nil {
				t.Fatal("missing host accepted")
			}
		})
	}
	d := passingEvidence()
	delete(d, "host_checks")
	if err := validate(d, reviewedSHA); err == nil {
		t.Fatal("absent host checks accepted")
	}
}
