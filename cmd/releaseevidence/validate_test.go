package main

import (
	"strings"
	"testing"
)

const reviewedSHA = "0123456789abcdef0123456789abcdef01234567"

func passingEvidence() map[string]any {
	scenarios := []any{}
	for id := range requiredCases() {
		requirements := []any{}
		for _, requirement := range []string{"AUTH-01", "AUTH-02", "AUTH-03", "AUTH-04", "AUTH-05", "AUTH-06", "AUTH-07", "AUTH-08", "AUTH-09", "AUTH-10"} {
			requirements = append(requirements, requirement)
		}
		scenarios = append(scenarios, map[string]any{
			"id": id, "source_sha": reviewedSHA, "release_blocking": true, "outcome": "pass",
			"requirement_ids": requirements, "preconditions": []any{"isolated fixture"}, "action": "exercise case",
			"command": "verified command", "redacted_evidence": "private evidence reference", "reviewer": "reviewer",
			"http_core_outcome":        map[string]any{"expected": "deny", "observed": "deny"},
			"durable_state_assertions": []any{"no forbidden writes"}, "security_event_observations": []any{"expected events"},
		})
	}
	gates := map[string]any{}
	for _, name := range []string{"candidate", "browser_and_hosts", "independent_review", "exposure_review", "private_reporting", "branch_and_tag_protection", "anonymous_exact_tag", "operational_drills"} {
		gates[name] = map[string]any{"status": "pass", "evidence": "private evidence reference"}
	}
	object(gates["candidate"])["source_sha"] = reviewedSHA
	object(gates["candidate"])["command"] = "make release-candidate-readiness"
	object(gates["anonymous_exact_tag"])["tag"] = "v0.5.0"
	profiles := map[string]any{}
	for _, id := range []string{"P1", "P2", "P3", "P4"} {
		profiles[id] = map[string]any{"status": "pass", "evidence": "private evidence"}
	}
	return map[string]any{
		"spec_version": 1, "candidate": map[string]any{"sha": reviewedSHA, "tag": "v0.5.0", "toolchain": "go1.27.1"},
		"scenarios": scenarios, "profiles": profiles, "release_gates": gates, "findings": []any{},
		"owner_approval": map[string]any{"release_claim": "public preview", "approved_by": "owner", "approved_on": "2026-09-29", "support_scope": "documented profiles"},
	}
}

func TestValidEvidence(t *testing.T) {
	if err := validate(passingEvidence(), reviewedSHA); err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceRejectsIncompleteOrStaleClaims(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"stale SHA", func(d map[string]any) { object(d["candidate"])["sha"] = "wrong" }},
		{"not run", func(d map[string]any) { object(d["scenarios"].([]any)[0])["outcome"] = "not_run" }},
		{"missing case", func(d map[string]any) { d["scenarios"] = d["scenarios"].([]any)[1:] }},
		{"duplicate", func(d map[string]any) { a := d["scenarios"].([]any); d["scenarios"] = append(a, a[0]) }},
		{"weakened blocking", func(d map[string]any) { object(d["scenarios"].([]any)[0])["release_blocking"] = false }},
		{"missing observations", func(d map[string]any) { delete(object(d["scenarios"].([]any)[0]), "durable_state_assertions") }},
		{"unapproved exclusion", func(d map[string]any) { object(d["scenarios"].([]any)[0])["outcome"] = "not_applicable" }},
		{"runner blocked", func(d map[string]any) { object(object(d["release_gates"])["candidate"])["status"] = "blocked" }},
		{"wrong tag", func(d map[string]any) { object(object(d["release_gates"])["anonymous_exact_tag"])["tag"] = "v0.4.1" }},
		{"open finding", func(d map[string]any) {
			d["findings"] = []any{map[string]any{"release_blocking": true, "status": "open"}}
		}},
		{"no owner", func(d map[string]any) { delete(d, "owner_approval") }},
		{"historical summary", func(d map[string]any) { d["scenarios"] = map[string]any{"SEC-01": "pass"} }},
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
	for _, entry := range d["scenarios"].([]any) {
		s := object(entry)
		if strings.HasPrefix(text(s["id"]), "OID-") {
			s["outcome"] = "not_applicable"
			s["not_applicable_reason"] = "OIDC not advertised"
			s["reviewer"] = "reviewer"
		}
	}
	if validate(d, reviewedSHA) == nil {
		t.Fatal("advertised profile exclusion accepted")
	}
	object(d["profiles"])["P4"] = map[string]any{"status": "not_applicable", "not_applicable_reason": "OIDC not advertised", "reviewer": "reviewer"}
	if err := validate(d, reviewedSHA); err != nil {
		t.Fatal(err)
	}
}
