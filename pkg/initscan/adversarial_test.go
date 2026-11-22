package initscan

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestInitScan_RejectsSymlinkManifestsAndDepth1Only(t *testing.T) {
	outside := t.TempDir()
	secretFile := filepath.Join(outside, "secret.json")
	if err := os.WriteFile(secretFile, []byte(`{"dependencies":{"openai":"1.0.0"}}`), 0600); err != nil {
		t.Fatal(err)
	}

	workspace := t.TempDir()
	// Plant symlinked package.json pointing outside workspace
	if err := os.Symlink(secretFile, filepath.Join(workspace, "package.json")); err != nil {
		t.Fatal(err)
	}
	// Plant deeply nested manifest in node_modules (must be ignored — depth 1 only)
	nestedDir := filepath.Join(workspace, "node_modules", "evil-pkg")
	if err := os.MkdirAll(nestedDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nestedDir, "package.json"), []byte(`{"dependencies":{"openai":"1.0.0"}}`), 0644); err != nil {
		t.Fatal(err)
	}

	res, err := Scan(ScanOptions{
		Dir:      workspace,
		LookPath: func(string) (string, error) { return "/bin/true", nil },
	})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
	if len(res.AISDKs) != 0 {
		t.Fatalf("expected symlinked and nested manifests to be ignored, got AI SDKs: %v", res.AISDKs)
	}
	if len(res.SkippedSymlinks) != 1 || res.SkippedSymlinks[0] != "package.json" {
		t.Fatalf("expected package.json in SkippedSymlinks, got: %v", res.SkippedSymlinks)
	}
}

func TestInitScan_BoundedReadOnOversizedManifest(t *testing.T) {
	workspace := t.TempDir()
	// Create a 2MB requirements.txt where "openai" only appears past the 256KB read cap.
	var big bytes.Buffer
	line := strings.Repeat("# padding comment line\n", 1)
	for big.Len() < 512*1024 {
		big.WriteString(line)
	}
	big.WriteString("openai==1.0.0\n")
	if err := os.WriteFile(filepath.Join(workspace, "requirements.txt"), big.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	res, err := Scan(ScanOptions{
		Dir:      workspace,
		LookPath: func(string) (string, error) { return "/bin/true", nil },
	})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatalf("bounded scan took too long: %v", time.Since(start))
	}
	// Bounded at 256KB so tail past cap was not read
	if len(res.AISDKs) != 0 {
		t.Fatalf("expected 256KB cap to stop reading before tail, got AI SDKs: %v", res.AISDKs)
	}
}

func TestInitScan_ConcurrentN8ReadOnly(t *testing.T) {
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "go.mod"), []byte("module example.com/test\ngo 1.27.4\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := Scan(ScanOptions{
				Dir:      workspace,
				LookPath: func(string) (string, error) { return "/bin/true", nil },
			})
			if err != nil {
				errs <- err
				return
			}
			var buf bytes.Buffer
			if err := res.Render(&buf, true, false); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("N=8 concurrent initscan failed: %v", err)
	}
}
