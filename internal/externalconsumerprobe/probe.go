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
	builder.WriteString("module ")
	builder.WriteString(cfg.ProbeModule)
	builder.WriteString("\n\ngo 1.26\n\nrequire ")
	builder.WriteString(cfg.ModulePath)
	builder.WriteString(" ")
	builder.WriteString(cfg.targetVersion())
	builder.WriteString("\n")

	if cfg.LocalPath != "" {
		builder.WriteString("\nreplace ")
		builder.WriteString(cfg.ModulePath)
		builder.WriteString(" => ")
		builder.WriteString(filepath.Clean(cfg.LocalPath))
		builder.WriteString("\n")
	}

	return builder.String(), nil
}

func (c Config) BuildProbeTest() (string, error) {
	cfg := c.normalized()
	if err := cfg.Validate(); err != nil {
		return "", err
	}

	var builder strings.Builder
	builder.WriteString("package probe\n\n")
	builder.WriteString("import (\n")
	builder.WriteString("\t\"testing\"\n")
	for _, pkg := range externalconsumer.SupportedPackages {
		fmt.Fprintf(&builder, "\t_ %q\n", pkg)
	}
	builder.WriteString(")\n\n")
	builder.WriteString("func TestSupportedPackagesCompile(t *testing.T) {}\n")

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
