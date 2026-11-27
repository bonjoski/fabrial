//go:build !windows

package topui

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/bonjoski/fabrial/pkg/doctor"
	"github.com/bonjoski/fabrial/pkg/procident"
)

var (
	// ErrSymlinkRejected is returned when a symlink is planted at a sensitive state path.
	ErrSymlinkRejected = errors.New("security violation: symlink rejected fail-closed")
	// ErrForeignUID is returned when a socket, directory, or DB file is owned by another UID.
	ErrForeignUID = errors.New("security violation: path owned by foreign UID")
	// ErrInsecureSocket is returned when a Unix socket fails mode/type/peer verification.
	ErrInsecureSocket = errors.New("security violation: insecure unix domain socket")
)

// uidOfFile extracts the owning UID from os.FileInfo; overridable in unit tests.
var currentUIDFunc = func() uint32 {
	return uint32(os.Getuid())
}

// VerifyDirOwned checks via Lstat that dir is a real directory (never a symlink)
// owned by the current effective UID.
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
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		if stat.Uid != currentUIDFunc() {
			return fmt.Errorf("%w: %s (uid=%d, expected=%d)", ErrForeignUID, dir, stat.Uid, currentUIDFunc())
		}
	}
	return nil
}

// VerifyRegularFileOwned checks via Lstat that both path and its parent directory are
// non-symlinks owned by the current effective UID, and that path is a regular file.
func VerifyRegularFileOwned(path string) error {
	parent := filepath.Dir(path)
	if err := VerifyDirOwned(parent); err != nil {
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
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		if stat.Uid != currentUIDFunc() {
			return fmt.Errorf("%w: %s (uid=%d, expected=%d)", ErrForeignUID, path, stat.Uid, currentUIDFunc())
		}
	}
	return nil
}

// VerifySocketOwned checks that socketPath (and its parent directory) is a non-symlink
// Unix domain socket with owner-only permissions owned by the current UID.
func VerifySocketOwned(socketPath string) error {
	parent := filepath.Dir(socketPath)
	if err := VerifyDirOwned(parent); err != nil {
		return err
	}
	fi, err := os.Lstat(socketPath)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlinkRejected, socketPath)
	}
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		if stat.Uid != currentUIDFunc() {
			return fmt.Errorf("%w: %s (uid=%d, expected=%d)", ErrForeignUID, socketPath, stat.Uid, currentUIDFunc())
		}
	}
	if ok, reason := doctor.VerifySocketSecurity(socketPath); !ok {
		return fmt.Errorf("%w: %s (%s)", ErrInsecureSocket, socketPath, reason)
	}
	return nil
}

// DialOwnedUnixSocket validates socket ownership and permissions via Lstat, dials the
// Unix domain socket under ctx deadline, and verifies kernel peer UID via SO_PEERCRED / LOCAL_PEERCRED.
func DialOwnedUnixSocket(ctx context.Context, socketPath string) (net.Conn, error) {
	if err := VerifySocketOwned(socketPath); err != nil {
		return nil, err
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, err
	}
	if err := procident.VerifyUnixPeerUID(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: peer credential mismatch on %s: %v", ErrForeignUID, socketPath, err)
	}
	return conn, nil
}
