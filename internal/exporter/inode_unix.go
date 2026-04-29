//go:build unix

package exporter

import (
	"os"
	"syscall"
)

// inodeOf returns a stable per-file identifier on Unix. Used by the
// dhcp_log tailer to detect log rotation: a renamed/recreated file has
// a different inode even if the path is unchanged.
func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}
