package status

import "syscall"

// blockSize is the unit of Linux's block counts: f_frsize, as df uses. f_bsize can be
// far larger (128 KiB on ZFS).
func blockSize(fs *syscall.Statfs_t) uint64 { return uint64(fs.Frsize) }
