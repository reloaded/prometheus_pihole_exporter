//go:build !unix

package exporter

import "os"

// inodeOf returns 0 on non-Unix platforms — rotation detection then
// falls back to the size-shrink check, which is good enough for the
// build to compile and the unit tests to pass.
func inodeOf(_ os.FileInfo) uint64 {
	return 0
}
