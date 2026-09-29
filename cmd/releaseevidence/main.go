// Command releaseevidence validates a complete public-preview evidence manifest.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func main() {
	file := flag.String("file", "", "external YAML evidence manifest for the clean checkout")
	version := flag.String("version", "", "selected release tag; when nonempty, candidate.tag must match")
	flag.Parse()
	if err := run(*file, *version); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_, _ = fmt.Fprintln(os.Stdout, "Evidence structure and source identity verified; observations require human review.")
}

func run(path, version string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("--file is required; no historical evidence is selected automatically")
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open release evidence: %w", err)
	}
	defer func() { _ = file.Close() }()
	const maxBytes = 2 << 20
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return fmt.Errorf("read release evidence: %w", err)
	}
	if len(data) > maxBytes {
		return errors.New("release evidence exceeds two MiB")
	}
	var document map[string]any
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode release evidence: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("decode trailing release evidence: %w", err)
		}
		return errors.New("exactly one YAML document is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tag := text(object(document["candidate"])["tag"])
	if version != "" && tag != version {
		return errors.New("candidate.tag must match --version")
	}
	if err := validateTagName(ctx, tag); err != nil {
		return err
	}
	head, err := exec.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
	if err != nil {
		return fmt.Errorf("resolve checkout HEAD: %w", err)
	}
	status, err := exec.CommandContext(ctx, "git", "status", "--porcelain", "--untracked-files=normal").Output()
	if err != nil {
		return fmt.Errorf("inspect checkout: %w", err)
	}
	if len(bytes.TrimSpace(status)) != 0 {
		return errors.New("evidence requires a clean checkout; keep the manifest outside the repository")
	}
	if err := validate(document, strings.TrimSpace(string(head))); err != nil {
		return err
	}
	// A matching string in a document is not proof that its tag resolves to HEAD.
	// The ref is a validated tag name passed as an argument, with no shell involved.
	//nolint:gosec // G204: validateTagName verifies this exact refs/tags ref before resolution.
	resolved, err := exec.CommandContext(ctx, "git", "rev-parse", "--verify", "refs/tags/"+tag+"^{commit}").Output()
	if err != nil {
		return fmt.Errorf("resolve candidate tag: %w", err)
	}
	if !bytes.Equal(bytes.TrimSpace(resolved), bytes.TrimSpace(head)) {
		return errors.New("candidate tag must exist locally and resolve to HEAD")
	}
	return nil
}

func validateTagName(ctx context.Context, tag string) error {
	if len(tag) < 2 || tag[0] != 'v' || tag[1] < '0' || tag[1] > '9' {
		return errors.New("candidate.tag must begin with v and a digit")
	}
	// Git performs the authoritative ref-name validation; arguments never go through a shell.
	//nolint:gosec // G204: this command validates the ref passed as a separate argument.
	err := exec.CommandContext(ctx, "git", "check-ref-format", "refs/tags/"+tag).Run()
	if err == nil {
		return nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return fmt.Errorf("invalid candidate tag name: %w", err)
	}
	return fmt.Errorf("validate candidate tag name: %w", err)
}
