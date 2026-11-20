//go:build !linux

package status

import "syscall"

// blockSize is the unit of the block counts; elsewhere Statfs_t has no f_frsize.
func blockSize(fs *syscall.Statfs_t) uint64 { return uint64(fs.Bsize) }
