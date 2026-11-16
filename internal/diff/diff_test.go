package diff

import (
	"reflect"
	"strings"
	"testing"
)

func TestLines(t *testing.T) {
	cases := []struct {
		name, a, b string
		want       []string
	}{
		{"equal", "a\nb\n", "a\nb\n", nil},
		{"new file", "", "a\nb\n", []string{"+ a", "+ b"}},
		{"removed file", "a\n", "", []string{"- a"}},
		{"changed line", "a\nb\nc\n", "a\nB\nc\n", []string{"- b", "+ B"}},
		{"added in middle", "a\nc\n", "a\nb\nc\n", []string{"+ b"}},
		{"removed at end", "a\nb\n", "a\n", []string{"- b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Lines(tc.a, tc.b); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Lines = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRedact(t *testing.T) {
	in := "[Interface]\nPrivateKey = AAAAsecretAAAA=\nAddress = 10.0.0.1/32\n[Peer]\nPublicKey = pubpub=\nPresharedKey = BBBBsecretBBBB=\n"
	out := Redact(in)
	for _, secret := range []string{"AAAAsecretAAAA=", "BBBBsecretBBBB="} {
		if strings.Contains(out, secret) {
			t.Errorf("Redact left %q in the output", secret)
		}
	}
	if !strings.Contains(out, "PublicKey = pubpub=") || !strings.Contains(out, "Address = 10.0.0.1/32") {
		t.Errorf("Redact changed non-secret lines:\n%s", out)
	}
	// A rotated key must still show up as a change.
	other := Redact(strings.Replace(in, "AAAAsecretAAAA=", "CCCCsecretCCCC=", 1))
	if len(Lines(out, other)) != 2 {
		t.Errorf("a changed key is not visible after redaction:\n%s\n%s", out, other)
	}
}
