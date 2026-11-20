package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xrvo/hearthgate/internal/config"
	"github.com/xrvo/hearthgate/internal/render"
)

const testConfig = `
edge:
  address: 198.51.100.7
publish:
  photos.example.net: immich-server:2283
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
		"generated/home/caddy/Caddyfile", "generated/home/stream/nginx.conf",
		"generated/home/tunnel/wg0.conf", "generated/home/tunnel/firewall.sh", "generated/home/tunnel/tunnel.env",
		"generated/edge/docker-compose.yml", "generated/edge/proxy/nginx.conf",
		"generated/edge/tunnel/wg0.conf", "generated/edge/tunnel/firewall.sh", "generated/edge/tunnel/tunnel.env",
	} {
		read(t, dir, f)
	}

	// A second init must not replace the keys. It reports where things stand.
	stateBefore := read(t, dir, "generated/state.json")
	code, out := ctl(t, dir, "", "init")
	if code != 0 || !strings.Contains(out, "Already set up") || !strings.Contains(out, "docker compose run --rm ctl check") {
		t.Errorf("second init: code %d\n%s", code, out)
	}
	if read(t, dir, "generated/state.json") != stateBefore {
		t.Error("second init replaced the keys")
	}

	if code, out := ctl(t, dir, "", "apply"); code != 0 || !strings.Contains(out, "Nothing to change") {
		t.Errorf("apply with no changes: code %d\n%s", code, out)
	}

	// Change a published target: declined first, then accepted.
	edgeBefore := read(t, dir, "generated/edge/docker-compose.yml")
	os.WriteFile(filepath.Join(dir, "hearthgate.yml"), []byte(strings.Replace(testConfig, "2283", "3000", 1)), 0o644)

	if _, out := ctl(t, dir, "", "init"); !strings.Contains(out, "hearthgate.yml has changed") || !strings.Contains(out, "ctl apply") {
		t.Errorf("init with a pending change does not point at apply:\n%s", out)
	}
	code, out = ctl(t, dir, "n\n", "apply")
	if code == 0 || !strings.Contains(out, "+ 	reverse_proxy immich-server:3000") {
		t.Errorf("declined apply: code %d\n%s", code, out)
	}
	if !strings.Contains(out, "Cancelled; nothing was written.") || strings.Contains(out, "error:") {
		t.Errorf("declining is reported as an error:\n%s", out)
	}
	if !strings.Contains(out, "This changes 2 generated files:") || !strings.Contains(out, "  home  2 files.") || strings.Contains(out, "  edge  ") {
		t.Errorf("summary does not say which side changes:\n%s", out)
	}
	if strings.Contains(read(t, dir, "generated/home/caddy/Caddyfile"), "3000") {
		t.Error("declined apply still wrote files")
	}

	code, out = ctl(t, dir, "y\n", "apply")
	if code != 0 || !strings.Contains(out, "docker compose up -d") {
		t.Errorf("accepted apply: code %d\n%s", code, out)
	}
	if !strings.Contains(read(t, dir, "generated/home/caddy/Caddyfile"), "immich-server:3000") {
		t.Error("accepted apply did not update the Caddyfile")
	}
	if !strings.Contains(out, "Next:") || !strings.Contains(out, "docker compose run --rm ctl check") {
		t.Errorf("apply does not end with the next commands:\n%s", out)
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

	// The example must be edited first: keys for a made-up VPS are no use.
	code, out = ctl(t, dir, "", "init")
	if code == 0 || !strings.Contains(out, "still has values from the example") {
		t.Fatalf("init with the unedited example: code %d\n%s", code, out)
	}
	for _, want := range []string{"address: 203.0.113.5", "ssh: ubuntu@203.0.113.5", "photos.example.com: immich-server:2283"} {
		if !strings.Contains(out, want) {
			t.Errorf("message does not point at %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "line ") != 3 {
		t.Errorf("message should name exactly the three lines to edit, comments excluded:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "generated")); err == nil {
		t.Error("init generated keys for the example's placeholder values")
	}

	// Once its placeholders are replaced, the example is a working config.
	edited := strings.NewReplacer("203.0.113.5", "198.51.100.7", "photos.example.com", "photos.example.net").Replace(read(t, dir, "hearthgate.yml"))
	os.WriteFile(filepath.Join(dir, "hearthgate.yml"), []byte(edited), 0o644)
	if code, out := ctl(t, dir, "", "init"); code != 0 || !strings.Contains(out, "Generated the tunnel keys") {
		t.Fatalf("init with the edited example: code %d\n%s", code, out)
	}
}

func TestPlaceholdersMatchWholeValues(t *testing.T) {
	for _, cfg := range []string{
		"edge: {address: 203.0.113.50}\npublish: {myphotos.example.com: app:80}\n",
		"edge: {address: 203.0.113.5.nip.io}\npublish: {a.example.com: app:80}\n",
		"edge: {address: 198.51.100.7}  # was 203.0.113.5\npublish: {a.example.com: app:80}\n",
	} {
		if got := placeholders([]byte(cfg)); len(got) != 0 {
			t.Errorf("placeholders(%q) = %q", cfg, got)
		}
	}
}

func TestNoTerminal(t *testing.T) {
	dir := project(t, testConfig)
	ctl(t, dir, "", "init")
	os.WriteFile(filepath.Join(dir, "hearthgate.yml"), []byte(strings.Replace(testConfig, "2283", "3000", 1)), 0o644)
	for _, cmd := range []string{"apply", "rotate"} {
		code, out := ctl(t, dir, "", cmd)
		if code == 0 || !strings.Contains(out, "no terminal to ask on") || !strings.Contains(out, "add -yes") {
			t.Errorf("%s with no terminal: code %d\n%s", cmd, code, out)
		}
	}
	if strings.Contains(read(t, dir, "generated/home/caddy/Caddyfile"), "3000") {
		t.Error("apply wrote files without an answer")
	}
}

func TestSubnetChangeIsFlagged(t *testing.T) {
	dir := project(t, testConfig)
	ctl(t, dir, "", "init")

	os.WriteFile(filepath.Join(dir, "hearthgate.yml"), []byte(testConfig+"networks: {dmz: 10.99.1.0/24}\n"), 0o644)
	_, out := ctl(t, dir, "n\n", "apply")
	if !strings.Contains(out, "changes the addresses of hearthgate-dmz at home") || !strings.Contains(out, "docker compose down") {
		t.Errorf("dmz subnet change not flagged:\n%s", out)
	}
	if strings.Contains(out, "hearthgate-mgmt") || strings.Contains(out, "hearthgate-agents on the edge") {
		t.Errorf("unchanged networks flagged:\n%s", out)
	}

	os.WriteFile(filepath.Join(dir, "hearthgate.yml"), []byte(testConfig+"networks: {agents: 10.99.3.0/24}\n"), 0o644)
	_, out = ctl(t, dir, "n\n", "apply")
	if !strings.Contains(out, "changes the subnet of hearthgate-agents on the edge") || strings.Contains(out, "at home") {
		t.Errorf("agents subnet change not flagged on its own:\n%s", out)
	}

	// An ordinary change carries no such note.
	os.WriteFile(filepath.Join(dir, "hearthgate.yml"), []byte(strings.Replace(testConfig, "2283", "3000", 1)), 0o644)
	if _, out := ctl(t, dir, "n\n", "apply"); strings.Contains(out, "subnet") || strings.Contains(out, "addresses of") {
		t.Errorf("ordinary change flagged:\n%s", out)
	}
}

// Installs from before the address ranges existed have networks without one.
// Adding it means recreating both networks, so the upgrade must say so.
func TestAddedRangeIsFlagged(t *testing.T) {
	dir := project(t, testConfig)
	if _, out := ctl(t, dir, "", "init"); strings.Contains(out, "addresses of") {
		t.Errorf("first run flagged a network change:\n%s", out)
	}

	env := filepath.Join(dir, ".env")
	data, err := os.ReadFile(env)
	if err != nil {
		t.Fatal(err)
	}
	var old []string
	for _, l := range strings.Split(string(data), "\n") {
		if !strings.Contains(l, "_RANGE=") {
			old = append(old, l)
		}
	}
	os.WriteFile(env, []byte(strings.Join(old, "\n")), 0o644)

	_, out := ctl(t, dir, "n\n", "apply")
	if !strings.Contains(out, "changes the addresses of hearthgate-dmz and hearthgate-mgmt at home") {
		t.Errorf("added ranges not flagged:\n%s", out)
	}
}

// A push that fails after the files were written must not leave the user
// with "Nothing to change" and a stale edge.
func TestFailedPushIsNotForgotten(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no ssh client: every push fails
	withSSH := strings.Replace(testConfig, "address: 198.51.100.7", "address: 198.51.100.7\n  ssh: me@198.51.100.7", 1)
	dir := project(t, withSSH)
	ctl(t, dir, "", "init")

	os.WriteFile(filepath.Join(dir, "hearthgate.yml"), []byte(strings.Replace(withSSH, "45876", "45877", 1)), 0o644)
	code, out := ctl(t, dir, "", "apply", "-yes")
	if code == 0 {
		t.Fatalf("apply succeeded without ssh:\n%s", out)
	}
	for _, want := range []string{"the edge was not updated", "the edge still runs the previous\nconfiguration", "docker compose run --rm ctl push"} {
		if !strings.Contains(out, want) {
			t.Errorf("failed apply lacks %q:\n%s", want, out)
		}
	}
	code, out = ctl(t, dir, "", "apply")
	if code != 0 || !strings.Contains(out, "Nothing to change") || !strings.Contains(out, "has not pushed this configuration to the edge") {
		t.Errorf("apply after a failed push: code %d\n%s", code, out)
	}

	code, out = ctl(t, dir, "", "rotate", "-yes")
	if code == 0 || !strings.Contains(out, "the edge still has the old ones") || !strings.Contains(out, "Do not run `docker compose up -d` yet") {
		t.Errorf("failed rotate: code %d\n%s", code, out)
	}

	// Without edge.ssh ctl never pushes, so it has nothing to remind about.
	manual := project(t, testConfig)
	ctl(t, manual, "", "init")
	if _, out := ctl(t, manual, "", "apply"); strings.Contains(out, "has not pushed") {
		t.Errorf("reminder shown without edge.ssh:\n%s", out)
	}
}

func TestPermissionHelp(t *testing.T) {
	err := withPermissionHelp(&os.PathError{Op: "open", Path: "generated/state.json", Err: os.ErrPermission})
	for _, want := range []string{"generated/state.json", ":/work:z", "chown"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("permission message lacks %q:\n%v", want, err)
		}
	}
	if other := errors.New("x"); withPermissionHelp(other) != other {
		t.Error("an unrelated error was changed")
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
	if !strings.Contains(out, "install the edge bundle on the VPS") || !strings.Contains(out, "ctl bundle | ssh") {
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

func TestBundle(t *testing.T) {
	dir := project(t, testConfig)
	if code, out := ctl(t, dir, "", "bundle"); code == 0 || !strings.Contains(out, "ctl init") {
		t.Errorf("bundle before init: code %d\n%s", code, out)
	}
	if code, out := ctl(t, dir, "", "init"); code != 0 {
		t.Fatalf("init failed:\n%s", out)
	}

	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"bundle", "-dir", dir}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("bundle failed:\n%s", stderr.String())
	}
	gz, err := gzip.NewReader(&stdout)
	if err != nil {
		t.Fatalf("bundle output is not gzip: %v", err)
	}
	got := map[string]string{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(tr)
		got[hdr.Name] = string(body)
	}
	for _, f := range []string{"docker-compose.yml", "proxy/nginx.conf", "tunnel/firewall.sh", "tunnel/wg0.conf", "tunnel/tunnel.env"} {
		if got[f] != read(t, dir, "generated/edge/"+f) {
			t.Errorf("bundle entry %s differs from generated/edge/%s", f, f)
		}
	}
	if len(got) != 5 {
		t.Errorf("bundle has %d entries, want 5", len(got))
	}

	// A stale bundle must not be handed out.
	os.WriteFile(filepath.Join(dir, "hearthgate.yml"), []byte(strings.Replace(testConfig, "45876", "45877", 1)), 0o644)
	if code, out := ctl(t, dir, "", "bundle"); code == 0 || !strings.Contains(out, "ctl apply") {
		t.Errorf("bundle with pending changes: code %d\n%s", code, out)
	}
}

func TestBundleRefusesTerminal(t *testing.T) {
	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		if tty, err = os.OpenFile("/dev/null", os.O_WRONLY, 0); err != nil {
			t.Skip("no character device to stand in for a terminal")
		}
	}
	defer tty.Close()
	if !isTerminal(tty) {
		t.Error("a character device is not seen as a terminal")
	}
	if isTerminal(&bytes.Buffer{}) {
		t.Error("a buffer is seen as a terminal")
	}
}

func TestManualInstallCommand(t *testing.T) {
	dir := project(t, strings.Replace(testConfig, "address: 198.51.100.7", "address: 198.51.100.7\n  ssh_port: 2222", 1))
	_, out := ctl(t, dir, "", "push")
	want := "docker compose run --rm -T ctl bundle | ssh -p 2222 <user>@198.51.100.7 'mkdir -p hearthgate && cd hearthgate && tar -xzf - && docker compose up -d --remove-orphans'"
	if !strings.Contains(out, want) || strings.Count(out, "'") != 2 {
		t.Errorf("manual install command is wrong or not safely quoted:\n%s", out)
	}
}

func TestEdgeCommandParsing(t *testing.T) {
	dir := project(t, testConfig)
	for _, args := range [][]string{
		{"edge"}, {"edge", "bogus"}, {"edge", "up", "extra"}, {"edge", "logs", "caddy"},
		{"edge", "logs", "proxy", "extra"}, {"edge", "logs", "-tail", "-1"},
	} {
		code, out := ctl(t, dir, "", args...)
		if code != 2 || !strings.Contains(out, "Usage: ctl edge") {
			t.Errorf("%v: code %d\n%s", args, code, out)
		}
	}
	// Without edge.ssh there is nothing to reach, whatever the command.
	for _, args := range [][]string{{"edge", "up"}, {"edge", "down", "-yes"}, {"edge", "logs", "-f", "-tail", "5", "tunnel"}, {"edge", "status"}} {
		code, out := ctl(t, dir, "", args...)
		if code != 1 || !strings.Contains(out, "edge.ssh is not set") {
			t.Errorf("%v: code %d\n%s", args, code, out)
		}
	}
	code, out := ctl(t, dir, "", "status")
	if code != 1 || !strings.Contains(out, "run `ctl init` first") {
		t.Errorf("status before init: code %d\n%s", code, out)
	}
	ctl(t, dir, "", "init")
	code, out = ctl(t, dir, "", "status")
	if code != 0 || !strings.Contains(out, "generated files match") || !strings.Contains(out, "skip  edge.ssh is not set") {
		t.Errorf("status without edge.ssh: code %d\n%s", code, out)
	}
}

func TestEdgeDownAsksFirst(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no ssh client: reaching the edge fails
	dir := project(t, strings.Replace(testConfig, "address: 198.51.100.7", "address: 198.51.100.7\n  ssh: me@198.51.100.7", 1))
	code, out := ctl(t, dir, "n\n", "edge", "down")
	if code != 1 || !strings.Contains(out, "Every published hostname goes offline") || !strings.Contains(out, "Cancelled") || strings.Contains(out, "Stopping") {
		t.Errorf("declined down: code %d\n%s", code, out)
	}
	if code, out := ctl(t, dir, "", "edge", "down"); code != 1 || !strings.Contains(out, "add -yes") {
		t.Errorf("down with no terminal: code %d\n%s", code, out)
	}
	if code, out := ctl(t, dir, "", "edge", "down", "-yes"); code != 1 || !strings.Contains(out, "Stopping the edge stack on me@198.51.100.7") {
		t.Errorf("down -yes: code %d\n%s", code, out)
	}
}

func TestParseEdgeState(t *testing.T) {
	st := parseEdgeState("::absent\n")
	if st.installed {
		t.Error("absent edge reported as installed")
	}
	st = parseEdgeState("::files\nabc123  docker-compose.yml\r\ndef456 *nginx.conf\n::running\ntunnel\n::tunnel\nKEY=\t1700000000\nnow\n1700000042\n")
	if !st.installed || !st.running["tunnel"] || st.running["proxy"] {
		t.Errorf("running = %v", st.running)
	}
	if st.sums["docker-compose.yml"] != "abc123" || st.sums["nginx.conf"] != "def456" {
		t.Errorf("sums = %v", st.sums)
	}
	if age, err := handshakeAge(st.handshake); err != nil || age != 42*time.Second {
		t.Errorf("handshake age = %v, %v", age, err)
	}

	bundle := render.Files{"a": {Content: []byte("abc")}, "b": {Content: []byte("x")}}
	sums := map[string]string{"a": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "b": "wrong"}
	if got := differing(bundle, sums); len(got) != 1 || got[0] != "b" {
		t.Errorf("differing = %v", got)
	}
	if got := differing(bundle, nil); len(got) != 2 {
		t.Errorf("differing with nothing on the edge = %v", got)
	}
}

func TestColor(t *testing.T) {
	changes := []change{{path: "generated/edge/proxy/nginx.conf", lines: []string{"- old", "+ new"}}}
	var plain, coloured bytes.Buffer
	(&app{out: &plain}).printChanges(changes)
	(&app{out: &coloured, color: true}).printChanges(changes)
	if strings.Contains(plain.String(), "\x1b") {
		t.Errorf("escape codes without a terminal:\n%q", plain.String())
	}
	for _, want := range []string{"\x1b[32m+ new\x1b[0m", "\x1b[31m- old\x1b[0m", "  edge  1 file."} {
		if !strings.Contains(coloured.String(), want) {
			t.Errorf("coloured diff lacks %q:\n%q", want, coloured.String())
		}
	}

	tty, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skip("no character device to stand in for a terminal")
	}
	defer tty.Close()
	t.Setenv("TERM", "xterm")
	t.Setenv("NO_COLOR", "")
	if !useColor(tty) {
		t.Error("no colour on a terminal")
	}
	t.Setenv("NO_COLOR", "1")
	if useColor(tty) || useColor(&plain) {
		t.Error("colour despite NO_COLOR, or without a terminal")
	}
}

func TestNextAlignsCommands(t *testing.T) {
	var out bytes.Buffer
	long := strings.Repeat("x", 80)
	(&app{out: &out}).next(step{"short", "one"}, step{long, "two"}, step{"a longer one", "three"})
	want := "\nNext:\n  short         # one\n  # two\n    " + long + "\n  a longer one  # three\n"
	if out.String() != want {
		t.Errorf("next printed:\n%q\nwant:\n%q", out.String(), want)
	}
}

func TestCheckHints(t *testing.T) {
	cfg, err := config.Parse([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	report := func(err error) string {
		var out bytes.Buffer
		r := &reporter{app: &app{out: &out}}
		tlsFailure(r, cfg, "photos.example.net", "198.51.100.7:443", err)
		if r.failed != 1 {
			t.Errorf("failures = %d", r.failed)
		}
		return out.String()
	}
	dial := report(&net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")})
	if !strings.Contains(dial, "cannot connect to the edge") || !strings.Contains(dial, "open 443/tcp") || !strings.Contains(dial, "ctl push") {
		t.Errorf("unreachable edge:\n%s", dial)
	}
	silent := report(io.EOF)
	if !strings.Contains(silent, "no TLS answer came back from home") || !strings.Contains(silent, "docker compose up -d") || !strings.Contains(silent, "DNS for photos.example.net must point at 198.51.100.7") {
		t.Errorf("silent home:\n%s", silent)
	}
	cert := report(x509.UnknownAuthorityError{})
	if !strings.Contains(cert, "is not valid") || !strings.Contains(cert, "docker compose logs caddy") {
		t.Errorf("untrusted certificate:\n%s", cert)
	}

	var out bytes.Buffer
	tunnelHints(&reporter{app: &app{out: &out}}, cfg)
	for _, want := range []string{"docker compose up -d", "open 51820/udp", "edge.address (198.51.100.7)", "ctl rotate"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("tunnel hints lack %q:\n%s", want, out.String())
		}
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
