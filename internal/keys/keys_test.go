package keys

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// RFC 7748 section 6.1 test vector.
func TestPublicMatchesRFC7748(t *testing.T) {
	priv, _ := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	want, _ := hex.DecodeString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")

	got, err := Public(base64.StdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatal(err)
	}
	if got != base64.StdEncoding.EncodeToString(want) {
		t.Errorf("public key = %s", got)
	}
}

func TestGeneratedKeys(t *testing.T) {
	a, err := NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewPrivate()
	if a == b {
		t.Error("two generated private keys are identical")
	}
	if _, err := Public(a); err != nil {
		t.Errorf("generated key has no public key: %v", err)
	}
	psk, err := NewPreshared()
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := base64.StdEncoding.DecodeString(psk); err != nil || len(raw) != 32 {
		t.Errorf("preshared key is not 32 bytes of base64: %q", psk)
	}
}

func TestPublicRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "not base64!", "c2hvcnQ="} {
		if _, err := Public(in); err == nil {
			t.Errorf("Public(%q) succeeded", in)
		}
	}
}
