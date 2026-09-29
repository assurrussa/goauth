package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestReleaseEvidenceCLI(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "releaseevidence")
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}
	cases := []struct{ name, expected string }{
		{"valid", "Evidence structure and source identity verified"},
		{"dirty", "clean checkout"},
		{"mismatched tag", "resolve to HEAD"},
		{"invalid tag", "invalid candidate tag name"},
		{"revision expression", "invalid candidate tag name"},
		{"non version tag", "begin with v and a digit"},
		{"missing tag", "resolve candidate tag"},
		{"malformed YAML", "decode release evidence"},
		{"multiple documents", "exactly one YAML document"},
		{"malformed trailing YAML", "decode trailing release evidence"},
		{"oversized", "exceeds two MiB"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := t.TempDir()
			git := cliGit(t, ctx, repo)
			git("init", "--quiet")
			git("commit", "--quiet", "--allow-empty", "-m", "fixture")
			git("tag", fixtureTag)
			if tc.name == "mismatched tag" {
				git("commit", "--quiet", "--allow-empty", "-m", "new HEAD")
			}
			head := git("rev-parse", "HEAD")
			evidence := passingEvidence()
			object(evidence["candidate"])["sha"] = head
			object(object(evidence["release_gates"])["candidate"])["source_sha"] = head
			for _, entry := range scenarioEntries(evidence) {
				object(entry)["source_sha"] = head
			}
			for _, name := range []string{hostSite, hostAdmin} {
				object(object(evidence["host_checks"])[name])[fieldResolvedSHA] = head
			}
			data := cliEvidenceData(t, evidence, tc.name)
			if tc.name == "dirty" {
				if err := os.WriteFile(filepath.Join(repo, "untracked"), []byte("fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			manifest := filepath.Join(t.TempDir(), "evidence.yaml")
			if err := os.WriteFile(manifest, data, 0o600); err != nil {
				t.Fatal(err)
			}
			status := git("status", "--porcelain", "--untracked-files=normal")
			command := exec.CommandContext(ctx, binary, "--file", manifest)
			command.Dir = repo
			output, err := command.CombinedOutput()
			if (err == nil) != (tc.name == "valid") || !strings.Contains(string(output), tc.expected) {
				t.Fatalf("CLI result %v, expected %q:\n%s", err, tc.expected, output)
			}
			assertCLIReadOnly(t, git, status, head)
		})
	}
}

func cliEvidenceData(t *testing.T, evidence map[string]any, name string) []byte {
	t.Helper()
	tag := fixtureTag
	switch name {
	case "invalid tag":
		tag = "v0..5"
	case "revision expression":
		tag = "v0.5.0^{commit}"
	case "non version tag":
		tag = "HEAD"
	case "missing tag":
		tag = "v9.0.0"
	}
	object(evidence["candidate"])["tag"] = tag
	object(object(evidence["release_gates"])["anonymous_exact_tag"])["tag"] = tag
	data, err := yaml.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	switch name {
	case "malformed YAML":
		data = []byte("candidate: [")
	case "multiple documents":
		data = append(data, []byte("\n---\n{}\n")...)
	case "malformed trailing YAML":
		data = append(data, []byte("\n---\n[\n")...)
	case "oversized":
		data = []byte(strings.Repeat("x", (2<<20)+1))
	}
	return data
}

func cliGit(t *testing.T, ctx context.Context, repo string) func(...string) string {
	t.Helper()
	return func(args ...string) string {
		t.Helper()
		command := exec.CommandContext(ctx, "git", args...)
		command.Dir = repo
		command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull,
			"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.invalid",
			"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.invalid")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, output)
		}
		return strings.TrimSpace(string(output))
	}
}

func assertCLIReadOnly(t *testing.T, git func(...string) string, status, head string) {
	t.Helper()
	if after := git("status", "--porcelain", "--untracked-files=normal"); after != status {
		t.Fatal("CLI mutated checkout")
	}
	if after := git("rev-parse", "HEAD"); after != head {
		t.Fatal("CLI moved HEAD")
	}
}
