//go:build unix

package remote

import (
	"os"
	"syscall"
)

// ownerOf returns the uid that owns path.
func ownerOf(path string) (int, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}
