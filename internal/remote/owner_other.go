//go:build !unix

package remote

func ownerOf(string) (int, bool) { return 0, false }
