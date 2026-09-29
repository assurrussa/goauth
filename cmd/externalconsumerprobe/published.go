package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func validateProbeMode(version, localPath, goModCache string, postgresIntegration bool, timeout time.Duration) error {
	if timeout <= 0 {
		return errors.New("probe timeout must be positive")
	}
	if version == "" {
		return nil
	}
	if localPath != "" {
		return errors.New("version and local-path are mutually exclusive")
	}
	if goModCache != "" {
		return errors.New("published probes require a fresh module cache; go-mod-cache is local-only")
	}
	if postgresIntegration {
		return errors.New("published probes are credential-free; run PostgreSQL integration with local-path")
	}
	if strings.TrimSpace(version) != version {
		return errors.New("published version must not contain surrounding whitespace")
	}

	return nil
}

// publishedCommandEnv deliberately does not inherit credentials, Go settings,
// proxy URLs, workspace overrides, or caches from the caller. The Go executable
// and OS certificate store remain trusted inputs; this is not an OS sandbox.
func publishedCommandEnv(workdir string) ([]string, error) {
	state := filepath.Join(workdir, ".probe-state")
	home := filepath.Join(state, "home")
	temp := filepath.Join(state, "tmp")
	cache := filepath.Join(state, "cache")
	config := filepath.Join(state, "config")
	gopath := filepath.Join(state, "gopath")
	modcache := filepath.Join(state, "gomodcache")
	buildcache := filepath.Join(state, "gocache")
	for _, dir := range []string{home, temp, cache, config, gopath, modcache, buildcache} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create isolated probe directory: %w", err)
		}
	}

	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"USERPROFILE=" + home,
		"APPDATA=" + config,
		"LOCALAPPDATA=" + cache,
		"XDG_CONFIG_HOME=" + config,
		"XDG_CACHE_HOME=" + cache,
		"TMPDIR=" + temp,
		"TMP=" + temp,
		"TEMP=" + temp,
		"GO111MODULE=on",
		"GOENV=off",
		"GOWORK=off",
		"GOAUTH=off",
		"GOTOOLCHAIN=auto",
		"GOPATH=" + gopath,
		"GOMODCACHE=" + modcache,
		"GOCACHE=" + buildcache,
		"GOPROXY=https://proxy.golang.org",
		"GOSUMDB=sum.golang.org",
		"GOPRIVATE=",
		"GONOPROXY=",
		"GONOSUMDB=",
		"GOINSECURE=",
		"GOVCS=*:off",
		// Make downloaded directories removable with the temporary workspace.
		"GOFLAGS=-modcacherw",
	}
	// Windows process creation and system commands may need these OS paths.
	for _, name := range []string{"SystemRoot", "WINDIR"} {
		if value := os.Getenv(name); value != "" {
			env = append(env, name+"="+value)
		}
	}

	return env, nil
}

//nolint:tagliatelle // go list -m -json uses Go's exported field names.
type moduleSelection struct {
	Path    string           `json:"Path"`
	Version string           `json:"Version"`
	Replace *json.RawMessage `json:"Replace"`
}

func verifyModuleSelection(data []byte, modulePath, version string) error {
	var selected moduleSelection
	if err := json.Unmarshal(data, &selected); err != nil {
		return fmt.Errorf("decode resolved module: %w", err)
	}
	if selected.Path != modulePath || selected.Version != version {
		return fmt.Errorf("resolved module %s@%s does not match requested %s@%s; use an exact version",
			selected.Path, selected.Version, modulePath, version)
	}
	if selected.Replace != nil {
		return errors.New("published module must not have a replacement")
	}

	return nil
}
