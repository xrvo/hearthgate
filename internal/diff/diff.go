// Package diff produces a small line diff for previewing config changes.
package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var reSecret = regexp.MustCompile(`(?m)^(\s*(?:PrivateKey|PresharedKey)\s*=\s*)(\S+)\s*$`)

// Redact replaces WireGuard secrets with a short fingerprint, so a diff shows
// that a key changed without printing it.
func Redact(s string) string {
	return reSecret.ReplaceAllStringFunc(s, func(line string) string {
		m := reSecret.FindStringSubmatch(line)
		sum := sha256.Sum256([]byte(m[2]))
		return m[1] + "<redacted " + hex.EncodeToString(sum[:4]) + ">"
	})
}

// Lines returns the removed ("-") and added ("+") lines that turn a into b,
// in order. It returns nil when the two are equal.
func Lines(a, b string) []string {
	if a == b {
		return nil
	}
	x, y := split(a), split(b)

	// Longest common subsequence table; these files are a few dozen lines.
	lcs := make([][]int, len(x)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(y)+1)
	}
	for i := len(x) - 1; i >= 0; i-- {
		for j := len(y) - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}

	var out []string
	i, j := 0, 0
	for i < len(x) && j < len(y) {
		switch {
		case x[i] == y[j]:
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			out = append(out, "- "+x[i])
			i++
		default:
			out = append(out, "+ "+y[j])
			j++
		}
	}
	for ; i < len(x); i++ {
		out = append(out, "- "+x[i])
	}
	for ; j < len(y); j++ {
		out = append(out, "+ "+y[j])
	}
	return out
}

func split(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}
