package main

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestBrowserSessionCoordinator(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("Node.js is required for browser coordinator unit tests")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "node", "--test", "app.test.mjs").CombinedOutput()
	if err != nil {
		t.Fatalf("browser coordinator tests: %v\n%s", err, output)
	}
}
