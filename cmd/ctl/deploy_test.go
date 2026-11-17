package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xrvo/hearthgate/internal/config"
)

func TestInitAsksAndGenerates(t *testing.T) {
	dir := t.TempDir()
	code, out := ctl(t, dir, "198.51.100.7\nubuntu\nPhotos.Example.net\nimmich-server:2283\n", "init")
	if code != 0 || !strings.Contains(out, "Generated the tunnel keys") {
		t.Fatalf("init with answers: code %d\n%s", code, out)
	}
	yml := read(t, dir, "hearthgate.yml")
	cfg, err := config.Parse([]byte(yml))
	if err != nil {
		t.Fatalf("written config is invalid: %v\n%s", err, yml)
	}
	if cfg.EdgeAddress != "198.51.100.7" || cfg.SSH != "ubuntu@198.51.100.7" || len(cfg.Publish) != 1 ||
		cfg.Publish[0].Hostname != "photos.example.net" || cfg.Publish[0].Target.String() != "immich-server:2283" || len(cfg.Agents) != 0 {
		t.Errorf("config does not hold the answers: %+v", cfg)
	}
	if !strings.Contains(yml, "# Optional settings") || !strings.Contains(yml, "#   wireguard_port: 51820") {
		t.Errorf("config lacks the notes on optional settings:\n%s", yml)
	}
	// Home first, then one command for the edge.
	up, deploy := strings.Index(out, "docker compose up -d"), strings.Index(out, "docker compose run --rm ctl deploy")
	if up < 0 || deploy < up {
		t.Errorf("next steps are not `up -d` then `deploy`:\n%s", out)
	}
	read(t, dir, "generated/state.json")
}

func TestInitReasksAndAllowsNoSSH(t *testing.T) {
	dir := t.TempDir()
	answers := "not an address!\n\n198.51.100.7\n\nBad_Host\nphotos.example.net\nnoport\napp:80\n"
	code, out := ctl(t, dir, answers, "init")
	if code != 0 {
		t.Fatalf("init: code %d\n%s", code, out)
	}
	for _, want := range []string{"is not a valid IP address or hostname", "the VPS address is needed", "is not a valid hostname", "must look like container:port", "ctl bundle | ssh"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	yml := read(t, dir, "hearthgate.yml")
	if cfg, err := config.Parse([]byte(yml)); err != nil || cfg.SSH != "" || !strings.Contains(yml, "# ssh: user@198.51.100.7") {
		t.Errorf("config without ssh is wrong: %v\n%s", err, yml)
	}
	if strings.Contains(out, "ctl deploy") {
		t.Errorf("deploy offered without edge.ssh:\n%s", out)
	}
}

func TestInitAcceptsFullSSHTarget(t *testing.T) {
	dir := t.TempDir()
	if code, out := ctl(t, dir, "198.51.100.7\ndeploy@vps.example.net\na.example.net\napp:80\n", "init"); code != 0 {
		t.Fatalf("init: code %d\n%s", code, out)
	}
	if !strings.Contains(read(t, dir, "hearthgate.yml"), "  ssh: deploy@vps.example.net\n") {
		t.Error("a full user@host answer was not kept as given")
	}
}

func TestInitAbandonedWritesNothing(t *testing.T) {
	dir := t.TempDir()
	code, out := ctl(t, dir, "198.51.100.7\nubuntu\n", "init")
	if code != 1 || !strings.Contains(out, "Cancelled") {
		t.Errorf("abandoned init: code %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "hearthgate.yml")); err == nil {
		t.Error("an abandoned init wrote a config")
	}
}

func TestAskStopsOnInterrupt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	pr, pw, _ := os.Pipe() // never written to: the read blocks
	defer pw.Close()
	defer pr.Close()
	code := run(ctx, []string{"init", "-dir", t.TempDir()}, pr, &out, &out)
	if code != 1 || !strings.Contains(out.String(), "Cancelled") {
		t.Errorf("interrupted prompt: code %d\n%s", code, out.String())
	}
}

func stubDNS(t *testing.T, records map[string][]string) {
	t.Helper()
	old := lookupHost
	lookupHost = func(_ context.Context, host string) ([]string, error) {
		if addrs, ok := records[host]; ok {
			return addrs, nil
		}
		return nil, errors.New("no such host")
	}
	t.Cleanup(func() { lookupHost = old })
}

func dnsReport(t *testing.T, cfgText string) (string, *reporter) {
	t.Helper()
	cfg, err := config.Parse([]byte(cfgText))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	r := &reporter{app: &app{out: &out}}
	r.app.reportDNS(context.Background(), r, cfg)
	return out.String(), r
}

func TestReportDNS(t *testing.T) {
	const cfg = "edge: {address: 198.51.100.7}\npublish: {a.example.net: app:80, b.example.net: app:80, c.example.net: app:80, d.example.net: app:80}\n"
	stubDNS(t, map[string][]string{
		"a.example.net": {"198.51.100.7"},
		"b.example.net": {"198.51.100.99"},
		"c.example.net": {"198.51.100.7", "2001:db8::1"},
	})
	out, r := dnsReport(t, cfg)
	for _, want := range []string{
		"ok    DNS: a.example.net points at the edge",
		"warn  DNS: b.example.net resolves to 198.51.100.99, which is not the edge (198.51.100.7)",
		"warn  DNS: c.example.net resolves to 2001:db8::1",
		"remove its AAAA (IPv6) record",
		"warn  DNS: d.example.net does not resolve yet; a certificate cannot be issued",
		"create a DNS record for d.example.net pointing at 198.51.100.7",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	if r.failed != 0 || r.warned != 3 {
		t.Errorf("failed = %d, warned = %d; DNS problems are warnings", r.failed, r.warned)
	}
	if strings.Count(out, "AAAA") != 1 {
		t.Errorf("the IPv6 hint belongs only under the hostname with a stray IPv6 address:\n%s", out)
	}
}

func TestReportDNSWithEdgeHostname(t *testing.T) {
	stubDNS(t, map[string][]string{
		"vps.example.net": {"198.51.100.7", "2001:db8::7"},
		"a.example.net":   {"::ffff:198.51.100.7", "2001:db8::7"},
	})
	out, r := dnsReport(t, "edge: {address: vps.example.net}\npublish: {a.example.net: app:80}\ntls: {ca: internal}\n")
	if !strings.Contains(out, "a.example.net points at the edge") || r.warned != 0 {
		t.Errorf("hostname matching the edge's addresses:\n%s", out)
	}

	stubDNS(t, nil)
	out, r = dnsReport(t, "edge: {address: vps.example.net}\npublish: {a.example.net: app:80}\n")
	if !strings.Contains(out, "edge.address vps.example.net does not resolve") || r.warned != 1 {
		t.Errorf("unresolvable edge:\n%s", out)
	}
}

func TestParsePreflight(t *testing.T) {
	p := parsePreflight("::docker\n29.9.3\n::compose\nv2.40.1\n::running\ntunnel\nproxy\n::listen\ntcp 0.0.0.0:22\ntcp [::]:443\nudp *:51820\ntcp 127.0.0.1:8080\n")
	if p.docker != "29.9.3" || p.compose != "v2.40.1" || !p.running["tunnel"] || !p.canList {
		t.Errorf("preflight = %+v", p)
	}
	for _, want := range []string{"tcp:22", "tcp:443", "udp:51820", "tcp:8080"} {
		if !p.listening[want] {
			t.Errorf("listening lacks %s: %v", want, p.listening)
		}
	}
	if p.listening["tcp:51820"] || p.listening["tcp:80"] {
		t.Errorf("listening has ports nothing holds: %v", p.listening)
	}
	if p := parsePreflight("::docker\n29.9.3\n::compose\n5.7.0\n::running\n"); p.canList {
		t.Error("ports reported as listable without a listing")
	}
}

func TestComposeTooOld(t *testing.T) {
	for v, want := range map[string]bool{
		"2.16.0": true, "v2.3.3": true, "1.29.2": true,
		"2.17.0": false, "v2.40.1": false, "5.7.0": false, "2.24.6-desktop.1": false, "": false, "dev": false,
	} {
		if got := composeTooOld(v); got != want {
			t.Errorf("composeTooOld(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestDeployNeedsSSHAndInit(t *testing.T) {
	dir := project(t, testConfig)
	if code, out := ctl(t, dir, "", "deploy"); code != 1 || !strings.Contains(out, "deploy needs edge.ssh") || !strings.Contains(out, "ctl bundle | ssh") {
		t.Errorf("deploy without edge.ssh: code %d\n%s", code, out)
	}
	withSSH := project(t, strings.Replace(testConfig, "address: 198.51.100.7", "address: 198.51.100.7\n  ssh: me@198.51.100.7", 1))
	if code, out := ctl(t, withSSH, "", "deploy"); code != 1 || !strings.Contains(out, "run `ctl init` first") {
		t.Errorf("deploy before init: code %d\n%s", code, out)
	}
}

// A VPS that cannot be reached stops the deploy before anything is written.
func TestDeployStopsAtPreflight(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no ssh client
	stubDNS(t, map[string][]string{"photos.example.net": {"198.51.100.7"}})
	withSSH := strings.Replace(testConfig, "address: 198.51.100.7", "address: 198.51.100.7\n  ssh: me@198.51.100.7", 1)
	dir := project(t, withSSH)
	ctl(t, dir, "", "init")
	os.WriteFile(filepath.Join(dir, "hearthgate.yml"), []byte(strings.Replace(withSSH, "2283", "3000", 1)), 0o644)

	code, out := ctl(t, dir, "", "deploy", "-yes")
	if code != 1 || !strings.Contains(out, "the VPS is not ready") || !strings.Contains(out, "Deploy stopped.") {
		t.Errorf("deploy with an unreachable VPS: code %d\n%s", code, out)
	}
	if !strings.Contains(out, "ok    DNS: photos.example.net points at the edge") {
		t.Errorf("preflight did not report DNS:\n%s", out)
	}
	if strings.Contains(read(t, dir, "generated/home/Caddyfile"), "3000") {
		t.Error("deploy wrote files although the preflight failed")
	}
}
