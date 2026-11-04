//go:build windows

package session

import (
	"os"
	"sync"
)

var winProcessMu sync.Mutex

// FileLock represents an advisory lock placeholder on Windows.
type FileLock struct {
	file *os.File
}

// AcquireFileLock provides in-process mutex locking on Windows.
func AcquireFileLock(lockPath string) (*FileLock, error) {
	winProcessMu.Lock()
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		winProcessMu.Unlock()
		return nil, err
	}
	return &FileLock{file: f}, nil
}

// Release releases the lock on Windows.
func (l *FileLock) Release() error {
	if l != nil && l.file != nil {
		_ = l.file.Close()
	}
	winProcessMu.Unlock()
	return nil
}
