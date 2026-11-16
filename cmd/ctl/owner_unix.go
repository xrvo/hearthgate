//go:build unix

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// dirOwner returns the owner of the project directory. Inside the ctl
// container that is the host user who checked the project out.
func dirOwner(dir string) (uid, gid int, ok bool) {
	info, err := os.Stat(dir)
	if err != nil {
		return 0, 0, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

// chownTree hands generated files back to the project owner. Failures are
// ignored: ownership is a convenience, not something the stacks depend on.
func chownTree(root string, uid, gid int) {
	filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err == nil {
			os.Lchown(path, uid, gid)
		}
		return nil
	})
}
