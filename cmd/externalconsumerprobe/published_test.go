package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testPublishedVersion = "v0.4.2"

func TestValidateProbeMode(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		version  string
		local    string
		cache    string
		postgres bool
		timeout  time.Duration
		wantErr  bool
	}{
		{name: "local", local: ".", cache: "cache", timeout: time.Minute},
		{name: "local postgres", local: ".", postgres: true, timeout: time.Minute},
		{name: "published", version: testPublishedVersion, timeout: time.Minute},
		{name: "mixed", version: testPublishedVersion, local: ".", timeout: time.Minute, wantErr: true},
		{name: "shared cache", version: testPublishedVersion, cache: "cache", timeout: time.Minute, wantErr: true},
		{name: "published postgres", version: testPublishedVersion, postgres: true, timeout: time.Minute, wantErr: true},
		{name: "whitespace", version: " v0.4.2", timeout: time.Minute, wantErr: true},
		{name: "zero timeout", local: ".", wantErr: true},
		{name: "negative timeout", local: ".", timeout: -time.Second, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateProbeMode(tc.version, tc.local, tc.cache, tc.postgres, tc.timeout)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateProbeMode() error = %v, want error = %v", err, tc.wantErr)
			}
		})
	}
}

func TestPublishedCommandEnvIsolation(t *testing.T) {
	const envOff = "off"
	for _, name := range []string{
		"HOME", "GOPATH", "GOMODCACHE", "GOCACHE", "GOENV", "GOWORK", "GOPROXY",
		"GOSUMDB", "GOAUTH", "GOFLAGS", "GOTOOLCHAIN", "GOVCS", "GOPRIVATE",
		"GONOPROXY", "GONOSUMDB", "GOINSECURE", "GITHUB_TOKEN", "GH_TOKEN",
		"GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL", "GIT_ASKPASS", "SSH_AUTH_SOCK",
		"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NETRC", "GOAUTH_TEST_POSTGRES_DSN",
	} {
		t.Setenv(name, "caller-private-value")
	}
	workdir := t.TempDir()
	env, err := publishedCommandEnv(workdir)
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]string, len(env))
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			t.Fatalf("invalid environment entry %q", entry)
		}
		if _, duplicate := values[key]; duplicate {
			t.Fatalf("duplicate environment key %q", key)
		}
		if strings.Contains(value, "caller-private-value") {
			t.Fatalf("caller environment leaked through %s", key)
		}
		values[key] = value
	}
	for name, want := range map[string]string{
		"GOENV": envOff, "GOWORK": envOff, "GOAUTH": envOff, "GO111MODULE": "on",
		"GOPROXY": "https://proxy.golang.org", "GOSUMDB": "sum.golang.org",
		"GOVCS": "*:off", "GOFLAGS": "-modcacherw", "GOTOOLCHAIN": "auto",
		"GOPRIVATE": "", "GONOPROXY": "", "GONOSUMDB": "", "GOINSECURE": "",
	} {
		if got, exists := values[name]; !exists || got != want {
			t.Errorf("%s = %q (present: %v), want %q", name, got, exists, want)
		}
	}
	for _, name := range []string{
		"GITHUB_TOKEN", "GH_TOKEN", "SSH_AUTH_SOCK", "NETRC", "HTTPS_PROXY",
		"HTTP_PROXY", "ALL_PROXY", "GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL",
		"GIT_ASKPASS", "GOAUTH_TEST_POSTGRES_DSN",
	} {
		if _, exists := values[name]; exists {
			t.Errorf("unexpected inherited environment key %s", name)
		}
	}
	for _, name := range []string{"HOME", "GOPATH", "GOMODCACHE", "GOCACHE", "TMPDIR", "XDG_CONFIG_HOME"} {
		rel, err := filepath.Rel(workdir, values[name])
		if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			t.Fatalf("%s is outside the isolated workspace", name)
		}
		entries, err := os.ReadDir(values[name])
		if err != nil || len(entries) != 0 {
			t.Fatalf("%s is not a fresh empty directory: %v", name, err)
		}
	}
}

func TestPublishedCommandEnvDirectoryFailure(t *testing.T) {
	t.Parallel()
	workdir := t.TempDir()
	if err := os.WriteFile(filepath.Join(workdir, ".probe-state"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := publishedCommandEnv(workdir); err == nil {
		t.Fatal("expected directory creation failure")
	}
}

func TestVerifyModuleSelection(t *testing.T) {
	t.Parallel()
	const modulePath = "github.com/assurrussa/goauth"
	cases := []struct {
		name    string
		data    string
		version string
		wantErr bool
	}{
		{name: "exact", data: `{"Path":"github.com/assurrussa/goauth","Version":"v0.4.2"}`, version: testPublishedVersion},
		{name: "prerelease", data: `{"Path":"github.com/assurrussa/goauth","Version":"v0.4.2-rc.1"}`, version: "v0.4.2-rc.1"},
		{name: "latest alias", data: `{"Path":"github.com/assurrussa/goauth","Version":"v0.4.2"}`, version: "latest", wantErr: true},
		{
			name:    "upgrade",
			data:    `{"Path":"github.com/assurrussa/goauth","Version":"v0.4.3"}`,
			version: testPublishedVersion,
			wantErr: true,
		},
		{
			name:    "replacement",
			data:    `{"Path":"github.com/assurrussa/goauth","Version":"v0.4.2","Replace":{}}`,
			version: testPublishedVersion,
			wantErr: true,
		},
		{name: "wrong module", data: `{"Path":"example.com/other","Version":"v0.4.2"}`, version: testPublishedVersion, wantErr: true},
		{name: "missing version", data: `{"Path":"github.com/assurrussa/goauth"}`, version: testPublishedVersion, wantErr: true},
		{name: "invalid json", data: `{`, version: testPublishedVersion, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := verifyModuleSelection([]byte(tc.data), modulePath, tc.version)
			if (err != nil) != tc.wantErr {
				t.Fatalf("verifyModuleSelection() error = %v, want error = %v", err, tc.wantErr)
			}
		})
	}
}
