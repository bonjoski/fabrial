package circuitbreaker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestAdversarial_FAB05_NoWorldWritableTmpSocketFallback verifies that resolveArgusSocketPath
// never falls back to world-writable /tmp/argus.sock and Tripwire refuses symlinked/0777 sockets.
func TestAdversarial_FAB05_NoWorldWritableTmpSocketFallback(t *testing.T) {
	t.Setenv("ARGUS_SOCKET", "")
	_ = os.Unsetenv("ARGUS_SOCKET")

	resolved := resolveArgusSocketPath()
	if resolved == "/tmp/argus.sock" || resolved == filepath.Join(os.TempDir(), "argus.sock") {
		t.Fatalf("FAIL-OPEN (FAB-05): resolveArgusSocketPath returned world-writable %s", resolved)
	}
	if !strings.Contains(resolved, ".argus") && !strings.Contains(resolved, fmt.Sprintf("%d", os.Getuid())) {
		t.Fatalf("expected user-scoped argus socket path, got %s", resolved)
	}

	if runtime.GOOS == "windows" {
		return
	}

	// Symlinked socket must be refused on Start()
	sockReal := filepath.Join(os.TempDir(), fmt.Sprintf("cb_real_%d.sock", time.Now().UnixNano()))
	sockSym := filepath.Join(os.TempDir(), fmt.Sprintf("cb_sym_%d.sock", time.Now().UnixNano()))
	_ = os.WriteFile(sockReal, []byte("target"), 0600)
	if err := os.Symlink(sockReal, sockSym); err != nil {
		t.Fatalf("symlink failed: %v", err)
	}
	defer func() {
		_ = os.Remove(sockSym)
		_ = os.Remove(sockReal)
	}()

	twSym := NewTripwire(TripwireOptions{SocketPath: sockSym})
	if err := twSym.Start(context.Background()); err == nil {
		_ = twSym.Stop()
		t.Fatal("FAIL-OPEN (FAB-05): Tripwire.Start accepted symlinked socket path")
	}

	// Pre-existing 0777 socket must be refused on Start()
	sock777 := filepath.Join(os.TempDir(), fmt.Sprintf("cb_777_%d.sock", time.Now().UnixNano()))
	ln, err := net.Listen("unix", sock777)
	if err != nil {
		t.Fatalf("listen 0777 socket: %v", err)
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove(sock777)
	}()
	_ = os.Chmod(sock777, 0777)

	tw777 := NewTripwire(TripwireOptions{SocketPath: sock777})
	if err := tw777.Start(context.Background()); err == nil {
		_ = tw777.Stop()
		t.Fatal("FAIL-OPEN (FAB-05): Tripwire.Start connected to world-writable 0777 socket")
	}
}

// TestAdversarial_FAB05_UnregisteredPIDNeverSignaledAndBoundedFrameRead verifies that
// Trip() refuses to signal unregistered PIDs and readLoop bounds frames to 64 KiB.
func TestAdversarial_FAB05_UnregisteredPIDNeverSignaledAndBoundedFrameRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix signal & socket test")
	}

	victim := exec.Command("sleep", "30")
	if err := victim.Start(); err != nil {
		t.Fatalf("start victim sleep: %v", err)
	}
	defer func() {
		_ = victim.Process.Kill()
		_ = victim.Wait()
	}()

	sockPath := filepath.Join(os.TempDir(), fmt.Sprintf("cb_bound_%d.sock", time.Now().UnixNano()))
	defer func() { _ = os.Remove(sockPath) }()

	tripCh := make(chan *TripResult, 2)
	tw := NewTripwire(TripwireOptions{
		SocketPath:  sockPath,
		ForensicDir: t.TempDir(),
		OnTrip: func(res *TripResult) {
			tripCh <- res
		},
	})
	if err := tw.Start(context.Background()); err != nil {
		t.Fatalf("tw.Start failed: %v", err)
	}
	defer func() { _ = tw.Stop() }()

	// 1. Send an oversized 128 KiB frame without newline — must be dropped cleanly without OOM/hang
	connBig, err := net.DialTimeout("unix", sockPath, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("dial sock: %v", err)
	}
	oversized := bytes.Repeat([]byte("A"), 128<<10)
	_, _ = connBig.Write(oversized)
	_ = connBig.Close()

	// 2. Send a valid JSON alert targeting UNREGISTERED victim.Process.Pid — must NOT freeze victim!
	conn, err := net.DialTimeout("unix", sockPath, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("dial sock after oversized frame: %v", err)
	}
	defer conn.Close()

	forgedAlert := &Alert{
		RuleName:  "spoofed_kill",
		Severity:  "CRITICAL",
		AgentPID:  victim.Process.Pid,
		SessionID: "unregistered-session",
	}
	raw, _ := json.Marshal(forgedAlert)
	raw = append(raw, '\n')
	if _, err := conn.Write(raw); err != nil {
		t.Fatalf("write alert: %v", err)
	}

	select {
	case res := <-tripCh:
		if res.Frozen {
			t.Fatalf("FAIL-OPEN (FAB-05): Tripwire froze UNREGISTERED PID %d!", victim.Process.Pid)
		}
		if !strings.Contains(res.Error, "unregistered PID") {
			t.Fatalf("expected unregistered PID refusal error, got: %q", res.Error)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tripwire unresponsive after oversized frame")
	}
}

// TestAdversarial_FAB06_PIDRecyclingStartTimeGuard verifies that FreezeVerified and Tripwire
// refuse to signal a live process if its kernel start timestamp differs from registration time.
func TestAdversarial_FAB06_PIDRecyclingStartTimeGuard(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix process start time check")
	}

	innocent := exec.Command("sleep", "30")
	if err := innocent.Start(); err != nil {
		t.Fatalf("start innocent process: %v", err)
	}
	defer func() {
		_ = innocent.Process.Kill()
		_ = innocent.Wait()
	}()

	// Simulate stale PID registration from an earlier exited child (start time mismatch by 10s)
	staleStartNs := time.Now().Add(-10 * time.Minute).UnixNano()
	_, err := FreezeVerified(innocent.Process.Pid, staleStartNs)
	if err == nil {
		_ = Unfreeze(innocent.Process.Pid)
		t.Fatal("FAIL-OPEN (FAB-06): FreezeVerified froze process despite mismatched start timestamp!")
	}
	if !errors.Is(err, ErrPIDRecycled) {
		t.Fatalf("expected ErrPIDRecycled, got: %v", err)
	}

	tw := NewTripwire(TripwireOptions{
		SocketPath:  filepath.Join(os.TempDir(), fmt.Sprintf("cb_recycle_%d.sock", time.Now().UnixNano())),
		ForensicDir: t.TempDir(),
	})
	tw.RegisterSessionPIDWithStartTime("sess-recycled", innocent.Process.Pid, staleStartNs)
	res := tw.Trip(&Alert{
		RuleName:  "late_alert",
		SessionID: "sess-recycled",
		AgentPID:  innocent.Process.Pid,
	})
	if res.Frozen {
		_ = Unfreeze(innocent.Process.Pid)
		t.Fatal("FAIL-OPEN (FAB-06): Tripwire froze recycled PID with mismatched start time!")
	}
}
