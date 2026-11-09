//go:build windows

package circuitbreaker

import (
	"fmt"
	"os/exec"
)

func verifyProcessTarget(pid int) error {
	return nil
}

func freezeProcessTree(pid int, _ int64) (string, error) {
	// Fallback to PowerShell process suspend on Windows
	cmd := exec.Command("powershell", "-NoProfile", "-Command", fmt.Sprintf("Get-Process -Id %d | ForEach-Object { $_.Suspend() }", pid))
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("windows process suspend failed: %w", err)
	}
	return "suspended", nil
}

func unfreezeProcessTree(pid int) error {
	cmd := exec.Command("powershell", "-NoProfile", "-Command", fmt.Sprintf("Get-Process -Id %d | ForEach-Object { $_.Resume() }", pid))
	return cmd.Run()
}
