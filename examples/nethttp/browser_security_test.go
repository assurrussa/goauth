package main

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestBrowserAcceptanceSecurityConfiguration(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("Node.js is required for browser security configuration tests")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "node", "--test", "browser-security.test.mjs").CombinedOutput()
	if err != nil {
		t.Fatalf("browser security configuration tests: %v\n%s", err, output)
	}
}
