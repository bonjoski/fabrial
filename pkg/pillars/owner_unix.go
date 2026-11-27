//go:build !windows

package pillars

import (
	"os"
	"syscall"
)

// isOwnedByCurrentUserOrRoot verifies via syscall.Stat_t that fi is owned by the
// invoking effective UID or root (UID 0, e.g. system/Homebrew installs), preventing
// other local users from planting binaries on shared workstations.
func isOwnedByCurrentUserOrRoot(fi os.FileInfo) bool {
	if fi == nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return false
	}
	euid := uint32(os.Geteuid())
	return st.Uid == euid || st.Uid == 0
}
