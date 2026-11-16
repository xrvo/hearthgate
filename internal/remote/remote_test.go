package remote

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"testing"
	"time"

	"github.com/xrvo/hearthgate/internal/render"
)

func TestArchiveRoundTrip(t *testing.T) {
	bundle := render.Files{
		"docker-compose.yml":          {Content: []byte("services: {}\n"), Mode: 0o644},
		"wireguard/wg_confs/wg0.conf": {Content: []byte("[Interface]\n"), Mode: 0o600},
	}
	data, err := Archive(bundle, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}

	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		want, ok := bundle[hdr.Name]
		if !ok {
			t.Fatalf("unexpected entry %q", hdr.Name)
		}
		body, _ := io.ReadAll(tr)
		if !bytes.Equal(body, want.Content) {
			t.Errorf("%s content = %q", hdr.Name, body)
		}
		if hdr.Mode != int64(want.Mode) {
			t.Errorf("%s mode = %o, want %o", hdr.Name, hdr.Mode, want.Mode)
		}
		seen[hdr.Name] = true
	}
	if len(seen) != len(bundle) {
		t.Errorf("archive has %d entries, want %d", len(seen), len(bundle))
	}
}
