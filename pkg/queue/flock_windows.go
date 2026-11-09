//go:build windows

package queue

import (
	"os"
)

func tryLockSlotFile(path string) (*os.File, bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, false, err
	}
	return f, true, nil
}

func unlockSlotFile(f *os.File) {
	if f != nil {
		_ = f.Close()
	}
}
