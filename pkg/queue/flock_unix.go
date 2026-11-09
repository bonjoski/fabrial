//go:build unix

package queue

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func tryLockSlotFile(path string) (*os.File, bool, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, false, fmt.Errorf("open lock file %s: %w", path, err)
	}

	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("flock %s: %w", path, err)
	}

	return os.NewFile(uintptr(fd), path), true, nil
}

func unlockSlotFile(f *os.File) {
	if f == nil {
		return
	}
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	_ = f.Close()
}
