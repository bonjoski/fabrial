package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestFabrialBinaryZeroTUIDependency enforces the RFC-2026-11-25-63 0.00ms Hop Tax invariant:
// cmd/fabrial MUST NEVER import pkg/topui, Bubble Tea, Lip Gloss, or modernc.org/sqlite.
func TestFabrialBinaryZeroTUIDependency(t *testing.T) {
	cmd := exec.Command("go", "list", "-f", "{{range .Deps}}{{println .}}{{end}}", ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps failed: %v\n%s", err, string(out))
	}
	deps := string(out)
	forbidden := []string{
		"github.com/bonjoski/fabrial/pkg/topui",
		"github.com/charmbracelet/bubbletea",
		"github.com/charmbracelet/lipgloss",
		"modernc.org/sqlite",
	}
	for _, pkg := range forbidden {
		if strings.Contains(deps, pkg) {
			t.Fatalf("HOT-PATH REGRESSION: cmd/fabrial illegally imports decoupled TUI/DB dependency %q", pkg)
		}
	}
}
