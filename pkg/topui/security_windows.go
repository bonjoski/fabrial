//go:build windows

package topui

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

var (
	ErrSymlinkRejected = errors.New("security violation: symlink rejected fail-closed")
	ErrForeignUID      = errors.New("security violation: path owned by foreign UID")
	ErrInsecureSocket  = errors.New("security violation: insecure unix domain socket")
)

// VerifyDirOwned rejects symlinked directories on Windows.
func VerifyDirOwned(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlinkRejected, dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("path %s is not a directory", dir)
	}
	return nil
}

// VerifyRegularFileOwned rejects symlinked files or parent directories on Windows.
func VerifyRegularFileOwned(path string) error {
	if err := VerifyDirOwned(filepath.Dir(path)); err != nil {
		return err
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlinkRejected, path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("path %s is not a regular file", path)
	}
	return nil
}

// VerifySocketOwned rejects symlinked socket paths on Windows.
func VerifySocketOwned(socketPath string) error {
	if err := VerifyDirOwned(filepath.Dir(socketPath)); err != nil {
		return err
	}
	fi, err := os.Lstat(socketPath)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlinkRejected, socketPath)
	}
	return nil
}

// DialOwnedUnixSocket validates socketPath and dials it with ctx deadline.
func DialOwnedUnixSocket(ctx context.Context, socketPath string) (net.Conn, error) {
	if err := VerifySocketOwned(socketPath); err != nil {
		return nil, err
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "unix", socketPath)
}
