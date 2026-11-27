//go:build windows

package pillars

import "os"

func isOwnedByCurrentUserOrRoot(fi os.FileInfo) bool {
	return fi != nil
}
