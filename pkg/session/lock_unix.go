//go:build !windows

package session

import (
	"os"
	"syscall"
)

// FileLock represents an advisory OS-level inter-process file lock.
type FileLock struct {
	file *os.File
}

// AcquireFileLock acquires an exclusive advisory lock using syscall.Flock.
func AcquireFileLock(lockPath string) (*FileLock, error) {
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &FileLock{file: f}, nil
}

// Release releases the advisory flock and closes the lockfile descriptor.
func (l *FileLock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	return l.file.Close()
}
