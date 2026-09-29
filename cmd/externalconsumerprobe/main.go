package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	externalconsumerprobe "github.com/assurrussa/goauth/internal/externalconsumerprobe"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		slog.Error("probe failed", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("externalconsumerprobe", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	modulePath := fs.String("module", externalconsumerprobe.DefaultModulePath, "target Go module path")
	version := fs.String("version", "", "exact published version to verify without credentials or existing caches")
	localPath := fs.String("local-path", "", "local checkout path for replace-based probe")
	goModCache := fs.String("go-mod-cache", "", "optional GOMODCACHE for local probes only")
	postgresIntegration := fs.Bool("postgres-integration", false,
		"exercise PostgreSQL Runtime, notifications, login, and RBAC using GOAUTH_TEST_POSTGRES_DSN")
	keepWorkdir := fs.Bool("keep-workdir", false, "keep the generated temporary probe module on disk")
	timeout := fs.Duration("timeout", 2*time.Minute, "timeout for each go command")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("external consumer probe does not accept positional arguments")
	}
	if err := validateProbeMode(*version, *localPath, *goModCache, *postgresIntegration, *timeout); err != nil {
		return err
	}

	cfg := externalconsumerprobe.Config{
		ModulePath: *modulePath,
		Version:    *version,
		LocalPath:  *localPath,
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if *postgresIntegration && strings.TrimSpace(os.Getenv("GOAUTH_TEST_POSTGRES_DSN")) == "" {
		return errors.New("GOAUTH_TEST_POSTGRES_DSN is required for the PostgreSQL external consumer probe")
	}

	workdir, err := os.MkdirTemp("", "goauth-externalconsumerprobe-*")
	if err != nil {
		return fmt.Errorf("create probe workdir: %w", err)
	}
	if !*keepWorkdir {
		defer func() {
			_ = os.RemoveAll(workdir)
		}()
	} else {
		// Print before any network call so a failed probe remains inspectable.
		_, _ = fmt.Fprintln(os.Stdout, workdir)
	}

	env := commandEnv(*goModCache)
	if cfg.Version != "" {
		env, err = publishedCommandEnv(workdir)
		if err != nil {
			return err
		}
		if err := checkModuleVersion(ctx, cfg.ModulePath, cfg.Version, workdir, env, *timeout, true); err != nil {
			return err
		}
	}

	if err := writeProbeFiles(cfg, workdir, *postgresIntegration); err != nil {
		return err
	}

	if err := goTestProbe(ctx, workdir, env, *timeout); err != nil {
		if *keepWorkdir {
			return fmt.Errorf("%w (workdir preserved at %s)", err, workdir)
		}
		return fmt.Errorf("%w (rerun with --keep-workdir to inspect generated probe module)", err)
	}
	if cfg.Version != "" {
		// Verify the version actually selected after test dependencies resolve.
		// Checking only module@version before the build is insufficient.
		return checkModuleVersion(ctx, cfg.ModulePath, cfg.Version, workdir, env, *timeout, false)
	}

	return nil
}

func writeProbeFiles(cfg externalconsumerprobe.Config, workdir string, postgresIntegration bool) error {
	goMod, err := cfg.BuildGoMod()
	if err != nil {
		return err
	}
	testFile, err := cfg.BuildProbeTest()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(workdir, "go.mod"), []byte(goMod), 0o600); err != nil {
		return fmt.Errorf("write probe go.mod: %w", err)
	}
	if err := os.WriteFile(filepath.Join(workdir, "externalconsumer_probe_test.go"), []byte(testFile), 0o600); err != nil {
		return fmt.Errorf("write probe test: %w", err)
	}
	if postgresIntegration {
		postgresTest, buildErr := cfg.BuildPostgresProbeTest()
		if buildErr != nil {
			return buildErr
		}
		if err := os.WriteFile(filepath.Join(workdir, "externalconsumer_postgres_test.go"), []byte(postgresTest), 0o600); err != nil {
			return fmt.Errorf("write PostgreSQL probe test: %w", err)
		}
	}

	return nil
}

func checkModuleVersion(
	ctx context.Context,
	modulePath, version, workdir string,
	env []string,
	timeout time.Duration,
	queryVersion bool,
) error {
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	query := modulePath
	if queryVersion {
		query += "@" + version
	}

	cmd := exec.CommandContext(commandCtx, "go", "list", "-m", "-json", query)
	cmd.Dir = workdir
	cmd.Env = env
	cmd.Stderr = os.Stderr
	data, err := cmd.Output()
	if err != nil {
		if errors.Is(commandCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("resolve published module %s: timeout after %s", query, timeout)
		}
		return fmt.Errorf("resolve published module %s: %w", query, err)
	}
	if err := verifyModuleSelection(data, modulePath, version); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stdout, "Verified module %s@%s (replacement: none)\n", modulePath, version)

	return nil
}

func goTestProbe(ctx context.Context, workdir string, env []string, timeout time.Duration) error {
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	//nolint:gosec // This release probe intentionally invokes the installed Go toolchain.
	cmd := exec.CommandContext(commandCtx, "go", probeTestArgs()...)
	cmd.Dir = workdir
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if errors.Is(commandCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("run external consumer probe: timeout after %s", timeout)
		}
		return fmt.Errorf("run external consumer probe: %w", err)
	}

	return nil
}

func probeTestArgs() []string {
	return []string{"test", "-mod=mod", "./...", "-count=1"}
}

func commandEnv(goModCache string) []string {
	parent := os.Environ()
	env := make([]string, 0, len(parent)+2)
	for _, entry := range parent {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, "GOWORK") || (goModCache != "" && strings.EqualFold(name, "GOMODCACHE")) {
			continue
		}
		env = append(env, entry)
	}
	env = append(env, "GOWORK=off")
	if goModCache != "" {
		env = append(env, "GOMODCACHE="+goModCache)
	}

	return env
}
