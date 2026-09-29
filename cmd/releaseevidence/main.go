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
	flag.Parse()
	if err := run(*file); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_, _ = fmt.Fprintln(os.Stdout, "Evidence structure and source identity verified; observations require human review.")
}

func run(path string) error {
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
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("exactly one YAML document is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
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
	tag := text(object(document["candidate"])["tag"])
	resolved, err := exec.CommandContext(ctx, "git", "rev-parse", "--verify", "refs/tags/"+tag+"^{commit}").Output()
	if err != nil || !bytes.Equal(bytes.TrimSpace(resolved), bytes.TrimSpace(head)) {
		return errors.New("candidate tag must exist locally and resolve to HEAD")
	}
	return nil
}
