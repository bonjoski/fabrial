//go:build windows

package doctor

import "os/exec"

func configureAirgapCmdProcessGroup(_ *exec.Cmd) {}

func terminateAirgapCmdProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
