package procident

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGetProcessStartTimeNs_CurrentAndChild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("kernel process start time attestation tested on unix")
	}

	selfNs, err := GetProcessStartTimeNs(os.Getpid())
	if err != nil {
		t.Fatalf("GetProcessStartTimeNs(self) failed: %v", err)
	}
	if selfNs <= 0 {
		t.Fatalf("expected positive start timestamp, got %d", selfNs)
	}

	cmd := exec.Command("sleep", "5")
	ConfigureChildProcGroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start sleep child: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	childNs, err := GetProcessStartTimeNs(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("GetProcessStartTimeNs(child) failed: %v", err)
	}
	if childNs < selfNs {
		t.Errorf("expected child start time (%d) >= parent start time (%d)", childNs, selfNs)
	}

	if _, err := GetProcessStartTimeNs(99999999); err == nil {
		t.Errorf("expected error on nonexistent PID")
	}
}

func TestVerifyUnixPeerUID_SameUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix domain peercred tested on unix")
	}

	sockPath := filepath.Join(os.TempDir(), "procident_peer.sock")
	_ = os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix failed: %v", err)
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove(sockPath)
	}()

	errCh := make(chan error, 1)
	go func() {
		srvConn, accErr := ln.Accept()
		if accErr != nil {
			errCh <- accErr
			return
		}
		defer srvConn.Close()
		errCh <- VerifyUnixPeerUID(srvConn)
	}()

	cliConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial unix failed: %v", err)
	}
	defer cliConn.Close()

	if err := VerifyUnixPeerUID(cliConn); err != nil {
		t.Fatalf("client VerifyUnixPeerUID failed: %v", err)
	}
	if srvErr := <-errCh; srvErr != nil {
		t.Fatalf("server VerifyUnixPeerUID failed: %v", srvErr)
	}
}
