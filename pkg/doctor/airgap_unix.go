//go:build !windows

package doctor

import (
	"os/exec"
	"syscall"
)

func configureAirgapCmdProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func terminateAirgapCmdProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	// Send SIGKILL to the entire process group to prevent orphaned child processes.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
