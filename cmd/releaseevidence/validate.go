package main

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

func requiredCases() map[string]bool {
	result := make(map[string]bool)
	for prefix, count := range map[string]int{"SEC": 20, "WEB": 8, "ADM": 4, "OID": 2, "OPS": 4} {
		for i := 1; i <= count; i++ {
			result[fmt.Sprintf("%s-%02d", prefix, i)] = true
		}
	}
	return result
}

func object(value any) map[string]any { result, _ := value.(map[string]any); return result }
func text(value any) string           { result, _ := value.(string); return strings.TrimSpace(result) }
func populatedList(value any) bool {
	entries, ok := value.([]any)
	if !ok || len(entries) == 0 {
		return false
	}
	for _, entry := range entries {
		if text(entry) == "" {
			return false
		}
	}
	return true
}

// validate checks evidence structure and provenance, not the truth of observations.
// The manifest belongs outside the clean checkout: a commit cannot name its own SHA.
func validate(doc map[string]any, head string) error {
	var problems []error
	add := func(format string, args ...any) { problems = append(problems, fmt.Errorf(format, args...)) }
	if !commitPattern.MatchString(head) {
		return errors.New("HEAD must be a full commit SHA")
	}
	if doc["spec_version"] != 1 {
		add("spec_version must be 1")
	}
	candidate := object(doc["candidate"])
	if text(candidate["sha"]) != head {
		add("candidate.sha must match clean HEAD")
	}
	if text(candidate["tag"]) == "" {
		add("candidate.tag is required")
	}
	if text(candidate["toolchain"]) == "" {
		add("candidate.toolchain is required")
	}
	scenarios, ok := doc["scenarios"].([]any)
	if !ok {
		add("scenarios must be the complete scenario list, not a historical summary")
	}
	missing := requiredCases()
	seen := make(map[string]bool)
	requirements := make(map[string]bool)
	profiles := object(doc["profiles"])
	for _, entry := range scenarios {
		scenario := object(entry)
		id := text(scenario["id"])
		if !requiredCases()[id] {
			add("unknown scenario %q", id)
			continue
		}
		if seen[id] {
			add("duplicate scenario %s", id)
			continue
		}
		seen[id] = true
		delete(missing, id)
		if scenario["release_blocking"] != true {
			add("%s must remain release-blocking", id)
		}
		if text(scenario["source_sha"]) != head {
			add("%s source SHA does not match HEAD", id)
		}
		ids, ok := scenario["requirement_ids"].([]any)
		if !ok {
			add("%s requirement_ids must be a list", id)
		}
		for _, value := range ids {
			req := text(value)
			if !regexp.MustCompile(`^AUTH-(0[1-9]|10)$`).MatchString(req) {
				add("%s has an invalid AUTH requirement", id)
			}
			requirements[req] = true
		}
		outcome := text(scenario["outcome"])
		switch outcome {
		case "pass":
			for _, field := range []string{"action", "command", "redacted_evidence", "reviewer"} {
				if text(scenario[field]) == "" {
					add("%s requires %s", id, field)
				}
			}
			for _, field := range []string{"preconditions", "durable_state_assertions", "security_event_observations"} {
				if !populatedList(scenario[field]) {
					add("%s requires nonempty %s", id, field)
				}
			}
			observation := object(scenario["http_core_outcome"])
			if text(observation["expected"]) == "" || text(observation["observed"]) == "" {
				add("%s requires expected and observed outcomes", id)
			}
		case "not_applicable":
			if text(scenario["not_applicable_reason"]) == "" || text(scenario["reviewer"]) == "" {
				add("%s requires a scope reason and reviewer approval", id)
			}
			profile := ""
			switch id[:3] {
			case "WEB":
				profile = "P2"
			case "ADM":
				profile = "P3"
			case "OID":
				profile = "P4"
			}
			if profile == "" || text(object(profiles[profile])["status"]) != "not_applicable" {
				add("%s cannot hide a required or advertised profile", id)
			}
		default:
			add("%s has blocking outcome %q", id, outcome)
		}
	}
	for id := range missing {
		add("missing scenario %s", id)
	}
	for i := 1; i <= 10; i++ {
		id := fmt.Sprintf("AUTH-%02d", i)
		if !requirements[id] {
			add("unmapped requirement %s", id)
		}
	}
	gates := object(doc["release_gates"])
	for _, name := range []string{"candidate", "browser_and_hosts", "independent_review", "exposure_review", "private_reporting", "branch_and_tag_protection", "anonymous_exact_tag", "operational_drills"} {
		gate := object(gates[name])
		if text(gate["status"]) != "pass" || text(gate["evidence"]) == "" {
			add("release gate %s requires pass and evidence", name)
		}
	}
	gate := object(gates["candidate"])
	if text(gate["source_sha"]) != head || text(gate["command"]) != "make release-candidate-readiness" {
		add("candidate gate must identify the exact SHA and command")
	}
	if text(object(gates["anonymous_exact_tag"])["tag"]) != text(candidate["tag"]) {
		add("anonymous exact-tag evidence must match candidate.tag")
	}
	for _, name := range []string{"P1", "P2", "P3", "P4"} {
		profile := object(profiles[name])
		switch text(profile["status"]) {
		case "pass":
			if text(profile["evidence"]) == "" {
				add("profile %s needs evidence", name)
			}
		case "not_applicable":
			if name == "P1" || text(profile["not_applicable_reason"]) == "" || text(profile["reviewer"]) == "" {
				add("profile %s needs a justified, approved exclusion", name)
			}
		default:
			add("profile %s remains unassessed", name)
		}
	}
	findings, ok := doc["findings"].([]any)
	if !ok {
		add("findings must be an explicit list")
	}
	for _, item := range findings {
		finding := object(item)
		if finding == nil {
			add("finding must be an object")
			continue
		}
		if finding["release_blocking"] == true && text(finding["status"]) != "resolved" {
			add("unresolved release-blocking finding")
		}
	}
	owner := object(doc["owner_approval"])
	for _, field := range []string{"release_claim", "approved_by", "approved_on", "support_scope"} {
		if text(owner[field]) == "" {
			add("owner_approval.%s is required", field)
		}
	}
	return errors.Join(problems...)
}
