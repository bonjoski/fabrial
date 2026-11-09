//go:build linux

package procident

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// GetProcessStartTimeNs reads field 22 (starttime ticks) from /proc/<pid>/stat
// safely handling arbitrary comm names containing spaces or parentheses.
func GetProcessStartTimeNs(pid int) (int64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("invalid pid: %d", pid)
	}
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		return 0, fmt.Errorf("failed to read %s: %w", statPath, err)
	}
	raw := string(data)
	closeParen := strings.LastIndexByte(raw, ')')
	if closeParen == -1 || closeParen+2 >= len(raw) {
		return 0, fmt.Errorf("malformed /proc/%d/stat format", pid)
	}
	fields := strings.Fields(raw[closeParen+2:])
	// Field 3 (state) is fields[0], so field 22 (starttime) is fields[19].
	if len(fields) <= 19 {
		return 0, fmt.Errorf("truncated /proc/%d/stat fields (%d)", pid, len(fields))
	}
	ticks, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil || ticks <= 0 {
		return 0, fmt.Errorf("invalid starttime in /proc/%d/stat: %w", pid, err)
	}
	return ticks, nil
}

// VerifyUnixPeerUID verifies via SO_PEERCRED (GetsockoptUcred) that the connected
// Unix domain socket peer runs under the same UID as the current process.
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

	var cred *unix.Ucred
	var sockErr error
	ctrlErr := rawConn.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if ctrlErr != nil {
		return fmt.Errorf("socket control error: %w", ctrlErr)
	}
	if sockErr != nil {
		return fmt.Errorf("getsockopt SO_PEERCRED failed: %w", sockErr)
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

// ConfigureChildProcGroup isolates a spawned child into its own process group (Setpgid: true).
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
