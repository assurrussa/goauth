package externalconsumerprobe

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	externalconsumer "github.com/assurrussa/goauth/reference/externalconsumer"
)

const (
	DefaultProbeModule = "example.com/goauthprobe"
	DefaultModulePath  = "github.com/assurrussa/goauth"
	LocalModuleVersion = "v0.0.0-local"
)

type Config struct {
	ProbeModule string
	ModulePath  string
	Version     string
	LocalPath   string
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.Version) == "" && strings.TrimSpace(c.LocalPath) == "" {
		return errors.New("external consumer probe: version or local path is required")
	}

	return nil
}

func (c Config) BuildGoMod() (string, error) {
	cfg := c.normalized()
	if err := cfg.Validate(); err != nil {
		return "", err
	}

	var builder strings.Builder
	_, _ = builder.WriteString("module ")
	_, _ = builder.WriteString(cfg.ProbeModule)
	_, _ = builder.WriteString("\n\ngo 1.26\n\nrequire ")
	_, _ = builder.WriteString(cfg.ModulePath)
	_, _ = builder.WriteString(" ")
	_, _ = builder.WriteString(cfg.targetVersion())
	_, _ = builder.WriteString("\n")

	if cfg.LocalPath != "" {
		_, _ = builder.WriteString("\nreplace ")
		_, _ = builder.WriteString(cfg.ModulePath)
		_, _ = builder.WriteString(" => ")
		_, _ = builder.WriteString(filepath.Clean(cfg.LocalPath))
		_, _ = builder.WriteString("\n")
	}

	return builder.String(), nil
}

func (c Config) BuildProbeTest() (string, error) {
	cfg := c.normalized()
	if err := cfg.Validate(); err != nil {
		return "", err
	}

	var builder strings.Builder
	_, _ = builder.WriteString("package probe\n\n")
	_, _ = builder.WriteString("import (\n")
	_, _ = builder.WriteString("\t\"testing\"\n")
	for _, pkg := range externalconsumer.SupportedPackages {
		_, _ = fmt.Fprintf(&builder, "\t_ %q\n", pkg)
	}
	_, _ = builder.WriteString(")\n\n")
	_, _ = builder.WriteString("func TestSupportedPackagesCompile(t *testing.T) {}\n")

	return builder.String(), nil
}

func (c Config) normalized() Config {
	cfg := c
	cfg.ProbeModule = strings.TrimSpace(cfg.ProbeModule)
	cfg.ModulePath = strings.TrimSpace(cfg.ModulePath)
	cfg.Version = strings.TrimSpace(cfg.Version)
	cfg.LocalPath = strings.TrimSpace(cfg.LocalPath)

	if cfg.ProbeModule == "" {
		cfg.ProbeModule = DefaultProbeModule
	}
	if cfg.ModulePath == "" {
		cfg.ModulePath = DefaultModulePath
	}

	return cfg
}

func (c Config) targetVersion() string {
	if strings.TrimSpace(c.Version) != "" {
		return strings.TrimSpace(c.Version)
	}

	return LocalModuleVersion
}
