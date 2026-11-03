package doctor

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDoctor_InspectAll_CanonicalOrdering(t *testing.T) {
	ctx := context.Background()
	inspector := NewInspector(1 * time.Second)

	results := inspector.InspectAll(ctx, ".")

	if len(results) != len(CanonicalOrder) {
		t.Fatalf("expected %d pillar reports, got %d", len(CanonicalOrder), len(results))
	}

	for i, pid := range CanonicalOrder {
		if results[i].Pillar != pid {
			t.Errorf("at index %d: expected pillar %s, got %s", i, pid, results[i].Pillar)
		}
	}
}

func TestDoctor_FormatTableAndJSON(t *testing.T) {
	ctx := context.Background()
	inspector := NewInspector(500 * time.Millisecond)

	results := inspector.InspectAll(ctx, ".")
	tbl := FormatTable(results)

	if !strings.Contains(tbl, "Fabrial Universal Security Fabric Diagnostic Suite") {
		t.Fatalf("table missing header: %s", tbl)
	}

	for _, pid := range CanonicalOrder {
		if !strings.Contains(tbl, string(pid)) {
			t.Errorf("table output missing pillar %s", pid)
		}
	}

	jsonBytes, err := FormatJSON(results)
	if err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}
	jsonStr := string(jsonBytes)
	for _, pid := range CanonicalOrder {
		if !strings.Contains(jsonStr, string(pid)) {
			t.Errorf("json output missing pillar %s", pid)
		}
	}
}

func TestDoctor_SocketSecurityVerification(t *testing.T) {
	// Use short path in os.TempDir() to avoid Darwin sockaddr_un 104-byte overflow
	sockPath := filepath.Join(os.TempDir(), fmt.Sprintf("doc-%d.sock", time.Now().UnixNano()))
	defer func() { _ = os.Remove(sockPath) }()

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen on test socket: %v", err)
	}
	defer ln.Close()

	// Default secure 0600
	_ = os.Chmod(sockPath, 0600)
	ok, reason := VerifySocketSecurity(sockPath)
	if !ok {
		t.Fatalf("expected 0600 socket to pass security check, failed: %s", reason)
	}

	// Insecure permissions 0666 (group/world writable)
	_ = os.Chmod(sockPath, 0666)
	ok, reason = VerifySocketSecurity(sockPath)
	if ok {
		t.Fatalf("expected 0666 socket to fail security check")
	}
	if !strings.Contains(reason, "insecure permissions") {
		t.Errorf("expected insecure permissions reason, got: %s", reason)
	}
}
