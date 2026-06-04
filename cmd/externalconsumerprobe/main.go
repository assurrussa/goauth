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
	"time"

	externalconsumerprobe "github.com/assurrussa/goauth/internal/externalconsumerprobe"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		slog.Error(err.Error(), "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("externalconsumerp robe", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	modulePath := fs.String("module", externalconsumerprobe.DefaultModulePath, "target Go module path")
	version := fs.String("version", "", "published target version to resolve and require")
	localPath := fs.String("local-path", "", "local checkout path for replace-based probe")
	goModCache := fs.String("go-mod-cache", "", "optional GOMODCACHE path for the probe commands")
	keepWorkdir := fs.Bool("keep-workdir", false, "keep the generated temporary probe module on disk")
	timeout := fs.Duration("timeout", 2*time.Minute, "timeout for each go command")

	if err := fs.Parse(args); err != nil {
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

	if cfg.Version != "" {
		if err := goListModule(ctx, cfg.ModulePath, cfg.Version, *goModCache, *timeout); err != nil {
			return err
		}
	}

	workdir, err := os.MkdirTemp("", "goauth-externalconsumerprobe-*")
	if err != nil {
		return fmt.Errorf("create probe workdir: %w", err)
	}
	if !*keepWorkdir {
		defer func() {
			_ = os.RemoveAll(workdir)
		}()
	}

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

	if err := goTestProbe(ctx, workdir, *goModCache, *timeout); err != nil {
		if *keepWorkdir {
			return fmt.Errorf("%w (workdir preserved at %s)", err, workdir)
		}
		return fmt.Errorf("%w (rerun with --keep-workdir to inspect generated probe module)", err)
	}

	if *keepWorkdir {
		_, _ = fmt.Fprintln(os.Stdout, workdir)
	}

	return nil
}

func goListModule(ctx context.Context, modulePath string, version string, goModCache string, timeout time.Duration) error {
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	//nolint:gosec // this is a probe intended to run go commands
	cmd := exec.CommandContext(commandCtx, "go", "list", "-m", "-json", modulePath+"@"+version)
	cmd.Env = commandEnv(goModCache)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if errors.Is(commandCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("resolve published module %s@%s: timeout after %s", modulePath, version, timeout)
		}
		return fmt.Errorf("resolve published module %s@%s: %w", modulePath, version, err)
	}

	return nil
}

func goTestProbe(ctx context.Context, workdir string, goModCache string, timeout time.Duration) error {
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	//nolint:gosec // this is a probe intended to run go commands
	cmd := exec.CommandContext(commandCtx, "go", probeTestArgs()...)
	cmd.Dir = workdir
	cmd.Env = commandEnv(goModCache)
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
	env := os.Environ()
	if goModCache == "" {
		return env
	}

	return append(env, "GOMODCACHE="+goModCache)
}
