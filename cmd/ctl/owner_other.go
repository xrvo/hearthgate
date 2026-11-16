//go:build !unix

package main

func dirOwner(string) (uid, gid int, ok bool) { return 0, 0, false }

func chownTree(string, int, int) {}
