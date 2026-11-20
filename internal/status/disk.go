package status

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// Disk is the usage of one filesystem, in bytes. Dev identifies the filesystem.
type Disk struct{ Used, Avail, Total, Dev uint64 }

// ReadDisk reads the filesystem holding path. A path that does not exist yet is
// read through its nearest existing parent.
func ReadDisk(path string) (Disk, error) {
	info, err := os.Stat(path)
	for errors.Is(err, os.ErrNotExist) {
		parent := filepath.Dir(path)
		if parent == path {
			break
		}
		path = parent
		info, err = os.Stat(path)
	}
	if err != nil {
		return Disk{}, err
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(path, &fs); err != nil {
		return Disk{}, err
	}
	bsize := blockSize(&fs)
	d := Disk{
		Used:  (uint64(fs.Blocks) - uint64(fs.Bfree)) * bsize,
		Avail: uint64(fs.Bavail) * bsize,
		Total: uint64(fs.Blocks) * bsize,
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		d.Dev = uint64(st.Dev)
	}
	return d, nil
}

// Percent is the share of usable space in use, matching df.
func (d Disk) Percent() float64 {
	if d.Used+d.Avail == 0 {
		return 0
	}
	return float64(d.Used) * 100 / float64(d.Used+d.Avail)
}
