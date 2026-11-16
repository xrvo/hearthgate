package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testConfig = `
edge:
  address: 203.0.113.5
publish:
  photos.example.com: immich-server:2283
agents:
  beszel: beszel-agent:45876
`

func ctl(t *testing.T, dir, stdin string, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	args = append(args[:1:1], append([]string{"-dir", dir}, args[1:]...)...)
	code := run(context.Background(), args, strings.NewReader(stdin), &out, &out)
	return code, out.String()
}

func project(t *testing.T, cfg string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hearthgate.yml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func read(t *testing.T, dir, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestInitThenApply(t *testing.T) {
	dir := project(t, testConfig)

	if code, out := ctl(t, dir, "", "init"); code != 0 {
		t.Fatalf("init failed:\n%s", out)
	}
	for _, f := range []string{
		"generated/state.json", ".env",
		"generated/home/Caddyfile", "generated/home/nginx.conf",
		"generated/home/wireguard/wg_confs/wg0.conf", "generated/home/wireguard/firewall.sh",
		"generated/edge/docker-compose.yml", "generated/edge/nginx.conf",
		"generated/edge/wireguard/wg_confs/wg0.conf", "generated/edge/wireguard/firewall.sh",
	} {
		read(t, dir, f)
	}

	// A second init must not replace the keys.
	if code, out := ctl(t, dir, "", "init"); code == 0 || !strings.Contains(out, "already initialised") {
		t.Errorf("second init: code %d\n%s", code, out)
	}

	if code, out := ctl(t, dir, "", "apply"); code != 0 || !strings.Contains(out, "Nothing to change") {
		t.Errorf("apply with no changes: code %d\n%s", code, out)
	}

	// Change a published target: declined first, then accepted.
	edgeBefore := read(t, dir, "generated/edge/docker-compose.yml")
	os.WriteFile(filepath.Join(dir, "hearthgate.yml"), []byte(strings.Replace(testConfig, "2283", "3000", 1)), 0o644)

	code, out := ctl(t, dir, "n\n", "apply")
	if code == 0 || !strings.Contains(out, "+ 	reverse_proxy immich-server:3000") {
		t.Errorf("declined apply: code %d\n%s", code, out)
	}
	if strings.Contains(read(t, dir, "generated/home/Caddyfile"), "3000") {
		t.Error("declined apply still wrote files")
	}

	code, out = ctl(t, dir, "y\n", "apply")
	if code != 0 || !strings.Contains(out, "docker compose up -d") {
		t.Errorf("accepted apply: code %d\n%s", code, out)
	}
	if !strings.Contains(read(t, dir, "generated/home/Caddyfile"), "immich-server:3000") {
		t.Error("accepted apply did not update the Caddyfile")
	}
	if strings.Contains(out, "edge bundle changed") || read(t, dir, "generated/edge/docker-compose.yml") != edgeBefore {
		t.Errorf("home-only change touched the edge:\n%s", out)
	}
}

func TestInitWritesStartingConfig(t *testing.T) {
	dir := t.TempDir()
	code, out := ctl(t, dir, "", "init")
	if code != 0 || !strings.Contains(out, "edit hearthgate.yml") {
		t.Fatalf("first init: code %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "generated")); err == nil {
		t.Error("first init generated keys before the config was edited")
	}

	// The config it wrote is a working example, so the second init completes.
	if code, out := ctl(t, dir, "", "init"); code != 0 || !strings.Contains(out, "Generated keys") {
		t.Fatalf("second init: code %d\n%s", code, out)
	}
	if code, out := ctl(t, dir, "", "apply"); code != 0 || !strings.Contains(out, "Nothing to change") {
		t.Errorf("apply after init: code %d\n%s", code, out)
	}
}

func TestApplyNeverPrintsSecrets(t *testing.T) {
	dir := project(t, testConfig)
	ctl(t, dir, "", "init")
	state := read(t, dir, "generated/state.json")

	code, out := ctl(t, dir, "", "rotate", "-yes")
	if code != 0 {
		t.Fatalf("rotate failed:\n%s", out)
	}
	newState := read(t, dir, "generated/state.json")
	if newState == state {
		t.Error("rotate did not change the keys")
	}
	if !strings.Contains(out, "<redacted") {
		t.Errorf("rotate diff does not show redacted key changes:\n%s", out)
	}
	for _, s := range []string{state, newState} {
		for _, line := range strings.Split(s, "\n") {
			parts := strings.Split(line, `"`)
			if len(parts) >= 4 && strings.HasSuffix(parts[1], "_key") && strings.Contains(out, parts[3]) {
				t.Errorf("output contains secret %s", parts[1])
			}
		}
	}
	// With no edge.ssh the user must be told to install the bundle by hand.
	if !strings.Contains(out, "Install it on the VPS") {
		t.Errorf("rotate did not explain the manual edge install:\n%s", out)
	}
}

func TestErrors(t *testing.T) {
	empty := t.TempDir()
	if code, out := ctl(t, empty, "", "apply"); code == 0 || !strings.Contains(out, "run `ctl init`") {
		t.Errorf("apply without config: code %d\n%s", code, out)
	}

	dir := project(t, testConfig)
	if code, out := ctl(t, dir, "", "apply"); code == 0 || !strings.Contains(out, "ctl init") {
		t.Errorf("apply before init: code %d\n%s", code, out)
	}
	if code, out := ctl(t, dir, "", "push"); code == 0 || !strings.Contains(out, "edge.ssh is not set") {
		t.Errorf("push without ssh: code %d\n%s", code, out)
	}
	if code, _ := ctl(t, dir, "", "bogus"); code != 2 {
		t.Errorf("unknown command: code %d", code)
	}

	bad := project(t, "edge: {address: ''}\npublish: {}\n")
	if code, out := ctl(t, bad, "", "init"); code == 0 || !strings.Contains(out, "edge.address is required") {
		t.Errorf("init with invalid config: code %d\n%s", code, out)
	}
}

func TestHandshakeAge(t *testing.T) {
	age, err := handshakeAge("abcKEY=\t1700000000\nnow\n1700000042\n")
	if err != nil || age != 42*time.Second {
		t.Errorf("age = %v, err = %v", age, err)
	}
	if _, err := handshakeAge("abcKEY=\t0\nnow\n1700000042\n"); err == nil || !strings.Contains(err.Error(), "never connected") {
		t.Errorf("zero handshake: err = %v", err)
	}
	if _, err := handshakeAge("garbage"); err == nil {
		t.Error("garbage output was accepted")
	}
}

func TestParseProbe(t *testing.T) {
	got := parseProbe("22 closed\n443 open\nnoise line here\n45876 closed\n")
	if got[22] != "closed" || got[443] != "open" || got[45876] != "closed" || len(got) != 3 {
		t.Errorf("parseProbe = %v", got)
	}
}
