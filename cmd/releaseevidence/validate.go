package main

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	hostSite             = "site"
	fieldEvidence        = "redacted_evidence"
	fieldResolvedVersion = "resolved_goauth_version"
	fieldResolvedSHA     = "resolved_goauth_sha"
	fieldOutcome         = "outcome"
	fieldCommand         = "command"
	fieldHostSHA         = "host_sha"
	fieldReplacement     = "replacement_present"
	outcomeBlocked       = "blocked"
	hostAdmin            = "admin"
	outcomePass          = "pass"
	outcomeExcluded      = "not_applicable"
	fieldReviewer        = "reviewer"
	fieldStatus          = "status"
	fieldReleaseBlocking = "release_blocking"
	findingResolved      = "resolved"
)

var requirementPattern = regexp.MustCompile(`^AUTH-(0[1-9]|10)$`)

var releaseGateNames = []string{
	"candidate", "browser_and_hosts", "independent_review", "exposure_review", "private_reporting",
	"branch_and_tag_protection", "anonymous_exact_tag", "operational_drills",
}

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

func object(value any) map[string]any {
	result, _ := value.(map[string]any)
	return result
}

func text(value any) string {
	result, _ := value.(string)
	return strings.TrimSpace(result)
}

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

type evidenceProblems []error

func (p *evidenceProblems) addf(format string, args ...any) {
	*p = append(*p, fmt.Errorf(format, args...))
}

// validate checks evidence structure and provenance, not the truth of observations.
// The manifest belongs outside the clean checkout: a commit cannot name its own SHA.
func validate(doc map[string]any, head string) error {
	var problems evidenceProblems
	addf := problems.addf
	if !commitPattern.MatchString(head) {
		return errors.New("HEAD must be a full commit SHA")
	}
	if doc["spec_version"] != 1 {
		addf("spec_version must be 1")
	}
	candidate := object(doc["candidate"])
	if text(candidate["sha"]) != head {
		addf("candidate.sha must match clean HEAD")
	}
	if text(candidate["tag"]) == "" {
		addf("candidate.tag is required")
	}
	if text(candidate["toolchain"]) == "" {
		addf("candidate.toolchain is required")
	}
	validateScenarios(doc, head, addf)
	validateHosts(object(doc["host_checks"]), head, addf)
	validateGates(object(doc["release_gates"]), candidate, head, addf)
	validateProfiles(object(doc["profiles"]), addf)
	validateFindings(doc["findings"], addf)
	owner := object(doc["owner_approval"])
	for _, field := range []string{"release_claim", "approved_by", "approved_on", "support_scope"} {
		if text(owner[field]) == "" {
			addf("owner_approval.%s is required", field)
		}
	}
	return errors.Join(problems...)
}

type addProblem func(string, ...any)

func validateScenarios(doc map[string]any, head string, addf addProblem) {
	scenarios, ok := doc["scenarios"].([]any)
	if !ok {
		addf("scenarios must be the complete scenario list, not a historical summary")
	}
	missing := requiredCases()
	seen := make(map[string]bool)
	requirements := make(map[string]bool)
	profiles := object(doc["profiles"])
	for _, entry := range scenarios {
		scenario := object(entry)
		id := text(scenario["id"])
		if !requiredCases()[id] {
			addf("unknown scenario %q", id)
			continue
		}
		if seen[id] {
			addf("duplicate scenario %s", id)
			continue
		}
		seen[id] = true
		delete(missing, id)
		validateScenario(scenario, id, profiles, head, addf)
		for _, req := range scenarioRequirements(scenario, id, addf) {
			requirements[req] = true
		}
	}
	for id := range missing {
		addf("missing scenario %s", id)
	}
	for i := 1; i <= 10; i++ {
		id := fmt.Sprintf("AUTH-%02d", i)
		if !requirements[id] {
			addf("unmapped requirement %s", id)
		}
	}
}

func validateGates(gates, candidate map[string]any, head string, addf addProblem) {
	for _, name := range releaseGateNames {
		gate := object(gates[name])
		if text(gate[fieldStatus]) != outcomePass || text(gate["evidence"]) == "" {
			addf("release gate %s requires pass and evidence", name)
		}
	}
	gate := object(gates["candidate"])
	if text(gate["source_sha"]) != head || text(gate[fieldCommand]) != "make release-candidate-readiness" {
		addf("candidate gate must identify the exact SHA and command")
	}
	if text(object(gates["anonymous_exact_tag"])["tag"]) != text(candidate["tag"]) {
		addf("anonymous exact-tag evidence must match candidate.tag")
	}
}

func validateProfiles(profiles map[string]any, addf addProblem) {
	for _, name := range []string{"P1", "P2", "P3", "P4"} {
		profile := object(profiles[name])
		switch text(profile[fieldStatus]) {
		case outcomePass:
			if text(profile["evidence"]) == "" {
				addf("profile %s needs evidence", name)
			}
		case outcomeExcluded:
			if name == "P1" || text(profile["not_applicable_reason"]) == "" || text(profile[fieldReviewer]) == "" {
				addf("profile %s needs a justified, approved exclusion", name)
			}
		default:
			addf("profile %s remains unassessed", name)
		}
	}
}

func validateFindings(value any, addf addProblem) {
	findings, ok := value.([]any)
	if !ok {
		addf("findings must be an explicit list")
	}
	for _, item := range findings {
		finding := object(item)
		if finding == nil {
			addf("finding must be an object")
			continue
		}
		blocking, ok := finding[fieldReleaseBlocking].(bool)
		if !ok {
			addf("finding release_blocking must be an explicit boolean")
			continue
		}
		if blocking && text(finding[fieldStatus]) != "resolved" {
			addf("unresolved release-blocking finding")
		}
	}
}

func validateScenario(scenario map[string]any, id string, profiles map[string]any, head string, addf addProblem) {
	blocking, _ := scenario[fieldReleaseBlocking].(bool)
	if !blocking {
		addf("%s must remain release-blocking", id)
	}
	if text(scenario["source_sha"]) != head {
		addf("%s source SHA does not match HEAD", id)
	}
	outcome := text(scenario[fieldOutcome])
	switch outcome {
	case outcomePass:
		for _, field := range []string{"action", fieldCommand, fieldEvidence, fieldReviewer} {
			if text(scenario[field]) == "" {
				addf("%s requires %s", id, field)
			}
		}
		for _, field := range []string{"preconditions", "durable_state_assertions", "security_event_observations"} {
			if !populatedList(scenario[field]) {
				addf("%s requires nonempty %s", id, field)
			}
		}
		observation := object(scenario["http_core_outcome"])
		if text(observation["expected"]) == "" || text(observation["observed"]) == "" {
			addf("%s requires expected and observed outcomes", id)
		}
	case outcomeExcluded:
		if text(scenario["not_applicable_reason"]) == "" || text(scenario[fieldReviewer]) == "" {
			addf("%s requires a scope reason and reviewer approval", id)
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
		if profile == "" || text(object(profiles[profile])[fieldStatus]) != outcomeExcluded {
			addf("%s cannot hide a required or advertised profile", id)
		}
	default:
		addf("%s has blocking outcome %q", id, outcome)
	}
}

func scenarioRequirements(scenario map[string]any, id string, addf addProblem) []string {
	ids, ok := scenario["requirement_ids"].([]any)
	if !ok {
		addf("%s requirement_ids must be a list", id)
	}
	result := make([]string, 0, len(ids))
	for _, value := range ids {
		req := text(value)
		if !requirementPattern.MatchString(req) {
			addf("%s has an invalid AUTH requirement", id)
		}
		result = append(result, req)
	}
	return result
}

func validateHosts(hosts map[string]any, head string, addf addProblem) {
	for _, name := range []string{hostSite, hostAdmin} {
		host := object(hosts[name])
		if text(host[fieldOutcome]) != outcomePass {
			addf("host_checks.%s requires a pass outcome", name)
		}
		if !commitPattern.MatchString(text(host[fieldHostSHA])) {
			addf("host_checks.%s requires a full host SHA", name)
		}
		if text(host[fieldResolvedSHA]) != head {
			addf("host_checks.%s resolved goauth SHA must match candidate.sha", name)
		}
		if _, ok := host[fieldReplacement].(bool); !ok {
			addf("host_checks.%s replacement_present must be an explicit boolean", name)
		}
		for _, field := range []string{fieldResolvedVersion, fieldCommand, fieldEvidence} {
			if text(host[field]) == "" {
				addf("host_checks.%s requires %s", name, field)
			}
		}
	}
}
