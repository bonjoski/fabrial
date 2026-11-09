//go:build darwin

// Package procident provides zero-CGO kernel process start-time and Unix peer UID attestation.
package procident

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// GetProcessStartTimeNs queries the Darwin kernel via sysctl kern.proc.pid
// to retrieve the nanosecond process creation timestamp, preventing PID-recycling attacks.
func GetProcessStartTimeNs(pid int) (int64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("invalid pid: %d", pid)
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, fmt.Errorf("sysctl kern.proc.pid.%d failed: %w", pid, err)
	}
	if kp == nil || int(kp.Proc.P_pid) != pid {
		return 0, fmt.Errorf("process %d not found in kernel table", pid)
	}
	ns := kp.Proc.P_starttime.Nano()
	if ns <= 0 {
		return 0, fmt.Errorf("invalid kernel start time for process %d", pid)
	}
	return ns, nil
}

// VerifyUnixPeerUID verifies via LOCAL_PEERCRED (GetsockoptXucred) that the connected
// Unix domain socket peer runs under the same effective UID as the current process.
func VerifyUnixPeerUID(conn net.Conn) error {
	if conn == nil {
		return errors.New("nil connection")
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("connection is not a unix domain socket")
	}
	rawConn, err := uc.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to inspect raw socket connection: %w", err)
	}

	var cred *unix.Xucred
	var sockErr error
	ctrlErr := rawConn.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	})
	if ctrlErr != nil {
		return fmt.Errorf("socket control error: %w", ctrlErr)
	}
	if sockErr != nil {
		return fmt.Errorf("getsockopt LOCAL_PEERCRED failed: %w", sockErr)
	}
	if cred == nil {
		return errors.New("empty peer credentials returned by kernel")
	}

	expectedUID := uint32(os.Getuid())
	if cred.Uid != expectedUID {
		return fmt.Errorf("unauthorized peer UID %d (expected %d)", cred.Uid, expectedUID)
	}
	return nil
}

// ConfigureChildProcGroup isolates a spawned child into its own process group (Setpgid: true)
// so process-group signaling (-pgid) captures forked descendants without affecting the parent.
func ConfigureChildProcGroup(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		return
	}
	cmd.SysProcAttr.Setpgid = true
}
