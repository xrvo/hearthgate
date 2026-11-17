package config

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// settings are the keys hearthgate.yml accepts at any level, used to suggest
// a correction for a misspelled one.
var settings = []string{
	"edge", "address", "ssh", "ssh_port", "dir", "wireguard_port", "https_port", "http_port",
	"publish", "agents", "target", "listen", "tls", "ca", "email",
	"tunnel", "subnet", "networks", "dmz", "mgmt",
}

var (
	reUnknownField = regexp.MustCompile(`^line (\d+): field (\S+) not found in type .+$`)
	reWrongType    = regexp.MustCompile("^line (\\d+): cannot unmarshal !!(\\w+)(?: `(.*)`)? into (.+)$")
)

// yamlError rewrites the YAML decoder's errors, which name Go types, in terms
// of the file the user is editing.
func yamlError(err error) error {
	if errors.Is(err, io.EOF) {
		return errors.New("the file is empty")
	}
	var te *yaml.TypeError
	if !errors.As(err, &te) {
		return fmt.Errorf("not valid YAML: %s", strings.TrimPrefix(err.Error(), "yaml: "))
	}
	var errs []error
	for _, e := range te.Errors {
		errs = append(errs, errors.New(friendly(e)))
	}
	return errors.Join(errs...)
}

func friendly(msg string) string {
	if m := reUnknownField.FindStringSubmatch(msg); m != nil {
		out := fmt.Sprintf("line %s: unknown setting %q", m[1], m[2])
		if s := closest(m[2]); s != "" {
			out += fmt.Sprintf(" (did you mean %q?)", s)
		}
		return out
	}
	if m := reWrongType.FindStringSubmatch(msg); m != nil {
		found := map[string]string{"seq": "a list", "map": "a group of settings", "null": "nothing"}[m[2]]
		if found == "" {
			found = fmt.Sprintf("%q", m[3])
		}
		var want string
		switch {
		case m[4] == "int":
			want = "a number"
		case m[4] == "string":
			want = "a single value"
		default:
			want = "a group of `key: value` lines"
		}
		return fmt.Sprintf("line %s: expected %s here, found %s", m[1], want, found)
	}
	return msg
}

// closest returns the known setting within two edits of s, if any.
func closest(s string) string {
	best, bestDist := "", 3
	for _, k := range settings {
		if d := distance(strings.ToLower(s), k); d < bestDist {
			best, bestDist = k, d
		}
	}
	return best
}

// distance is the Levenshtein edit distance.
func distance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}
