//go:build windows

package doctor

import "os"

// VerifySocketSecurity validates socket permissions on Windows.
func VerifySocketSecurity(path string) (bool, string) {
	fi, err := os.Lstat(path)
	if err != nil {
		return false, "socket file not accessible"
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return false, "insecure symlink detected (symlinked sockets forbidden)"
	}
	return true, ""
}

func isOwnedByCurrentUser(_ os.FileInfo) bool {
	return true
}
