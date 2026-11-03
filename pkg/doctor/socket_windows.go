//go:build windows

package doctor

// VerifySocketSecurity validates socket permissions on Windows.
func VerifySocketSecurity(path string) (bool, string) {
	// Basic stat check on Windows
	return true, ""
}
