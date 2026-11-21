package render

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/xrvo/hearthgate/internal/config"
	"github.com/xrvo/hearthgate/internal/keys"
	"github.com/xrvo/hearthgate/internal/state"
)

var testImages = Images{WireGuard: "linuxserver/wireguard:9.9.99999999", Nginx: "nginx:9.98-alpine"}

const sample = `
edge:
  address: 203.0.113.5
publish:
  photos.example.com: immich-server:2283
  docs.example.com: paperless:8000
agents:
  beszel: beszel-agent:45876
  web: {target: some-agent:80, listen: 18080}
`

func mustRender(t *testing.T, yaml string) (Files, *state.State) {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	st, err := state.New()
	if err != nil {
		t.Fatal(err)
	}
	files, err := Render(cfg, st, testImages, nil)
	if err != nil {
		t.Fatal(err)
	}
	return files, st
}

func content(t *testing.T, files Files, path string) string {
	t.Helper()
	f, ok := files[path]
	if !ok {
		t.Fatalf("%s was not rendered; have %v", path, files.Paths())
	}
	return string(f.Content)
}

func wantAll(t *testing.T, name, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("%s is missing %q:\n%s", name, w, got)
		}
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	cfg, _ := config.Parse([]byte(sample))
	st, _ := state.New()
	a, err := Render(cfg, st, testImages, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Render(cfg, st, testImages, nil)
	for _, p := range a.Paths() {
		if !bytes.Equal(a[p].Content, b[p].Content) {
			t.Errorf("%s differs between two renders", p)
		}
	}
}

func TestWireGuardConfs(t *testing.T) {
	files, st := mustRender(t, sample)
	homePub, _ := keys.Public(st.HomePrivate)
	edgePub, _ := keys.Public(st.EdgePrivate)

	home := content(t, files, HomeDir+"tunnel/wg0.conf")
	wantAll(t, "home wg0.conf", home,
		"PrivateKey = "+st.HomePrivate, "PublicKey = "+edgePub,
		"Endpoint = 203.0.113.5:51820", "AllowedIPs = 10.210.0.1/32", "PersistentKeepalive = 25")
	if strings.Contains(home, st.EdgePrivate) {
		t.Error("home wg0.conf contains the edge private key")
	}

	edge := content(t, files, EdgeDir+"tunnel/wg0.conf")
	wantAll(t, "edge wg0.conf", edge,
		"ListenPort = 51820", "PrivateKey = "+st.EdgePrivate,
		"PublicKey = "+homePub, "AllowedIPs = 10.210.0.2/32")
	if strings.Contains(edge, "Endpoint") {
		t.Error("edge wg0.conf has an Endpoint; home must be the side that dials")
	}

	wantAll(t, "home wg0.conf", home, "Address = 10.210.0.2/32")
	wantAll(t, "edge wg0.conf", edge, "Address = 10.210.0.1/32")

	// wg-quick in linuxserver/wireguard brings these up. The firewall must be
	// loaded in PreUp, before the interface comes up, never in PostUp; and
	// nothing may route more than the peer's own address or change DNS.
	for _, conf := range []string{home, edge} {
		wantAll(t, "wg0.conf", conf, "MTU = 1420", "PreUp = sh /config/wg_confs/firewall.sh %i")
		for _, bad := range []string{"PostUp", "DNS", "0.0.0.0/0", "SaveConfig"} {
			if strings.Contains(conf, bad) {
				t.Errorf("wg0.conf has %q:\n%s", bad, conf)
			}
		}
	}

	for _, p := range []string{HomeDir + "tunnel/wg0.conf", EdgeDir + "tunnel/wg0.conf"} {
		if files[p].Mode != 0o600 {
			t.Errorf("%s mode = %o, want 600", p, files[p].Mode)
		}
	}
}

// The edge bundle is everything the low-trust side receives.
func TestEdgeBundleHoldsNoHomeSecrets(t *testing.T) {
	files, st := mustRender(t, sample)
	for p, f := range files.WithPrefix(EdgeDir) {
		s := string(f.Content)
		if strings.Contains(s, st.HomePrivate) {
			t.Errorf("edge file %s contains the home private key", p)
		}
		for _, leak := range []string{"immich-server", "paperless", "photos.example.com", "docs.example.com"} {
			if strings.Contains(s, leak) {
				t.Errorf("edge file %s reveals home detail %q", p, leak)
			}
		}
	}
}

func TestHomeFirewall(t *testing.T) {
	files, _ := mustRender(t, sample)
	fw := content(t, files, HomeDir+"tunnel/firewall.sh")
	wantAll(t, "home firewall", fw,
		"iptables -P INPUT DROP", "iptables -P FORWARD DROP",
		`iptables -A INPUT -i "$WG" -s 10.210.0.1 -d 10.210.0.2 -p tcp --dport 443 -j ACCEPT`,
		`iptables -A INPUT ! -i "$WG" -s 10.210.2.0/24 -d 10.210.2.2 -p tcp --dport 45876 -j ACCEPT`,
		`iptables -A INPUT ! -i "$WG" -s 10.210.2.0/24 -d 10.210.2.2 -p tcp --dport 18080 -j ACCEPT`,
		`iptables -A OUTPUT -o "$WG" -j DROP`)

	// Exactly one rule may accept new connections arriving from the tunnel.
	n := 0
	for _, line := range strings.Split(fw, "\n") {
		if strings.HasPrefix(line, `iptables -A INPUT -i "$WG"`) && strings.HasSuffix(line, "ACCEPT") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("home firewall accepts %d kinds of connection from the tunnel, want exactly 1", n)
	}
	if strings.Contains(fw, "-A FORWARD") || strings.Contains(fw, "-t nat") {
		t.Error("home firewall must not forward or NAT")
	}
	if strings.Contains(fw, "\r") {
		t.Error("firewall script has CR line endings")
	}
}

func TestEdgeFirewall(t *testing.T) {
	files, _ := mustRender(t, sample)
	fw := content(t, files, EdgeDir+"tunnel/firewall.sh")
	wantAll(t, "edge firewall", fw,
		"iptables -P INPUT DROP", "iptables -P FORWARD DROP",
		`iptables -A INPUT -i "$WG" -s 10.210.0.2 -d 10.210.0.1 -p tcp --dport 45876 -j ACCEPT`,
		`iptables -A INPUT -i "$WG" -s 10.210.0.2 -d 10.210.0.1 -p tcp --dport 18080 -j ACCEPT`)
	if strings.Contains(fw, "-A FORWARD") || strings.Contains(fw, "-t nat") {
		t.Error("edge firewall must not forward or NAT")
	}
}

func TestCaddyfile(t *testing.T) {
	files, _ := mustRender(t, sample)
	c := content(t, files, HomeDir+"caddy/Caddyfile")
	wantAll(t, "Caddyfile", c,
		"default_bind 10.210.0.2", "allow 10.210.0.1/32", "fallback_policy reject",
		"disable_http_challenge", "admin off",
		"photos.example.com {\n\treverse_proxy immich-server:2283\n}",
		"docs.example.com {\n\treverse_proxy paperless:8000\n}")
	if strings.Contains(c, "local_certs") || strings.Contains(c, "staging") {
		t.Errorf("default CA should be production Let's Encrypt:\n%s", c)
	}

	internal, _ := mustRender(t, sample+"tls: {ca: internal, email: me@example.com}\n")
	ci := content(t, internal, HomeDir+"caddy/Caddyfile")
	wantAll(t, "internal Caddyfile", ci, "local_certs", "email me@example.com")
	if strings.Contains(ci, "cert_issuer") {
		t.Error("internal CA must not configure ACME")
	}

	staging, _ := mustRender(t, sample+"tls: {ca: letsencrypt-staging}\n")
	wantAll(t, "staging Caddyfile", content(t, staging, HomeDir+"caddy/Caddyfile"),
		"dir https://acme-staging-v02.api.letsencrypt.org/directory", "disable_http_challenge")
}

func TestStreamProxies(t *testing.T) {
	files, _ := mustRender(t, sample)

	home := content(t, files, HomeDir+"stream/nginx.conf")
	wantAll(t, "home nginx.conf", home,
		"listen 10.210.2.2:45876;", "proxy_pass 10.210.0.1:45876;",
		"listen 10.210.2.2:18080;", "proxy_pass 10.210.0.1:18080;")

	edge := content(t, files, EdgeDir+"proxy/nginx.conf")
	wantAll(t, "edge nginx.conf", edge,
		"listen 443;", "proxy_pass 10.210.0.2:443;", "proxy_protocol on;",
		"listen 10.210.0.1:45876;", `45876 "beszel-agent:45876";`,
		"listen 10.210.0.1:18080;", `18080 "some-agent:80";`,
		"return 301 https://$host$request_uri;")
	if strings.Contains(edge, "ssl_certificate") {
		t.Error("edge must not terminate TLS")
	}
}

func TestNoAgents(t *testing.T) {
	files, _ := mustRender(t, "edge: {address: 203.0.113.5}\npublish: {a.example.com: app:80}\n")
	edge := content(t, files, EdgeDir+"proxy/nginx.conf")
	if strings.Contains(edge, "agent_upstream") || strings.Contains(edge, "resolver") {
		t.Errorf("edge nginx.conf mentions agents when none are configured:\n%s", edge)
	}
	if strings.Contains(content(t, files, HomeDir+"stream/nginx.conf"), "listen") {
		t.Error("home nginx.conf listens when no agents are configured")
	}
}

func TestCustomPorts(t *testing.T) {
	files, _ := mustRender(t, "edge: {address: vps.example.net, https_port: 8443, http_port: 8080, wireguard_port: 51900}\npublish: {a.example.com: app:80}\n")
	wantAll(t, "edge nginx.conf", content(t, files, EdgeDir+"proxy/nginx.conf"), "return 301 https://$host:8443$request_uri;")
	wantAll(t, "edge compose", content(t, files, EdgeDir+"docker-compose.yml"),
		`"51900:51820/udp"`, `"8443:443"`, `"8080:80"`, "image: "+testImages.WireGuard, "image: "+testImages.Nginx, "name: hearthgate-agents")
	wantAll(t, "home wg0.conf", content(t, files, HomeDir+"tunnel/wg0.conf"), "Endpoint = vps.example.net:51900")
}

func TestHashesTrackContent(t *testing.T) {
	envHash := func(f Files) string {
		for _, line := range strings.Split(content(t, f, EnvFile), "\n") {
			if v, ok := strings.CutPrefix(line, "HEARTHGATE_CONFIG_HASH="); ok {
				return v
			}
		}
		t.Fatal("no HEARTHGATE_CONFIG_HASH in .env")
		return ""
	}
	cfgA, _ := config.Parse([]byte(sample))
	cfgB, _ := config.Parse([]byte(strings.Replace(sample, "paperless:8000", "paperless:8001", 1)))
	st, _ := state.New()
	a, _ := Render(cfgA, st, testImages, nil)
	b, _ := Render(cfgB, st, testImages, nil)

	if envHash(a) == envHash(b) {
		t.Error("home hash did not change when a published target changed")
	}
	// A home-only change must not restart the edge.
	if !bytes.Equal(a[EdgeDir+"docker-compose.yml"].Content, b[EdgeDir+"docker-compose.yml"].Content) {
		t.Error("edge compose changed for a home-only change")
	}
}

// No container may be handed another's files: the proxies run beside a tunnel
// and must not be able to read its keys.
func TestEachContainerGetsItsOwnDirectory(t *testing.T) {
	files, st := mustRender(t, sample)
	for p, f := range files {
		holdsKey := strings.Contains(string(f.Content), st.HomePrivate) || strings.Contains(string(f.Content), st.EdgePrivate) ||
			strings.Contains(string(f.Content), st.Preshared)
		inTunnel := strings.HasPrefix(p, HomeDir+"tunnel/") || strings.HasPrefix(p, EdgeDir+"tunnel/")
		if holdsKey && !inTunnel {
			t.Errorf("%s holds key material outside a tunnel directory", p)
		}
	}
	edge := content(t, files, EdgeDir+"docker-compose.yml")
	wantAll(t, "edge compose", edge, "- ./tunnel:/config/wg_confs:ro", "- ./proxy:/etc/hearthgate:ro")
	if strings.Count(edge, "NET_ADMIN") != 1 || strings.Count(edge, "image: "+testImages.WireGuard) != 1 || strings.Count(edge, "image: "+testImages.Nginx) != 1 {
		t.Errorf("edge compose should run the tunnel on linuxserver/wireguard, the proxy on nginx, and grant NET_ADMIN once:\n%s", edge)
	}

	data, err := os.ReadFile("../../docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	home := string(data)
	wantAll(t, "home compose", home,
		"- ./generated/home/tunnel:/config/wg_confs:ro", "- ./generated/home/caddy:/etc/hearthgate:ro", "- ./generated/home/stream:/etc/hearthgate:ro")
	if strings.Count(home, "NET_ADMIN") != 1 {
		t.Errorf("home compose should grant NET_ADMIN to the gateway only:\n%s", home)
	}
}

// Users copy the home compose file on its own, so it must run without a
// source checkout. It names each image once, behind an anchor, and passes
// the WireGuard and nginx images to ctl so the edge runs the same versions.
func TestHomeComposeImages(t *testing.T) {
	data, err := os.ReadFile("../../docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	compose := string(data)
	if n := strings.Count(compose, "ghcr.io/"); n != 1 {
		t.Errorf("docker-compose.yml names the Hearthgate image %d times; want once, behind the &image anchor, for ctl", n)
	}
	for _, want := range []struct {
		snippet string
		n       int
	}{
		{"image: *image\n", 1},     // ctl
		{"image: *wireguard\n", 1}, // gateway
		{"image: *caddy\n", 1},     // caddy
		{"image: *nginx\n", 1},     // stream
		{"HEARTHGATE_WIREGUARD_IMAGE: *wireguard", 1},
		{"HEARTHGATE_NGINX_IMAGE: *nginx", 1},
	} {
		if n := strings.Count(compose, want.snippet); n != want.n {
			t.Errorf("docker-compose.yml has %q %d times; want %d", want.snippet, n, want.n)
		}
	}
	if strings.Contains(compose, "build:") {
		t.Error("docker-compose.yml needs a source checkout to build")
	}
}

// Upstream images are pinned by version tag, at the level where upstream ships
// only fixes, and never by digest: see "Upstream versions" in CONTRIBUTING.md.
func TestUpstreamImagesPinnedByVersionTag(t *testing.T) {
	compose, err := os.ReadFile("../../docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	dockerfile, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"docker-compose.yml": string(compose), "Dockerfile": string(dockerfile)} {
		if strings.Contains(text, "sha256:") {
			t.Errorf("%s pins an image by digest", name)
		}
	}
	for _, want := range []struct{ file, text, pattern, why string }{
		{"docker-compose.yml", string(compose), `(?m)^x-wireguard: &wireguard linuxserver/wireguard:1\.0\.\d{8}$`, "a wireguard-tools release, e.g. linuxserver/wireguard:1.0.20260223, which follows linuxserver's rebuilds"},
		{"docker-compose.yml", string(compose), `(?m)^x-nginx: &nginx nginx:1\.\d*[02468]-alpine$`, "nginx's stable branch (an even minor), e.g. nginx:1.30-alpine"},
		{"docker-compose.yml", string(compose), `(?m)^x-caddy: &caddy caddy:2\.\d+-alpine$`, "a Caddy minor release, e.g. caddy:2.11-alpine"},
		{"Dockerfile", string(dockerfile), `(?m)^FROM alpine:3\.\d+$`, "an Alpine branch, e.g. alpine:3.24"},
		{"Dockerfile", string(dockerfile), `(?m)^FROM --platform=\$BUILDPLATFORM golang:1\.\d+-alpine AS build$`, "a Go minor release, e.g. golang:1.27-alpine"},
	} {
		if !regexp.MustCompile(want.pattern).MatchString(want.text) {
			t.Errorf("%s should pin %s", want.file, want.why)
		}
	}
}

// The WireGuard containers run as the owner of their read-only files, so
// linuxserver's start-up has nothing to chown: home from .env, which ctl
// writes, and the edge from the .env its install script writes.
func TestWireGuardRunsAsFileOwner(t *testing.T) {
	cfg, err := config.Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	st, err := state.New()
	if err != nil {
		t.Fatal(err)
	}
	files, err := Render(cfg, st, testImages, &Owner{UID: 1001, GID: 1002})
	if err != nil {
		t.Fatal(err)
	}
	wantAll(t, ".env", content(t, files, EnvFile), "\nHEARTHGATE_PUID=1001\n", "\nHEARTHGATE_PGID=1002\n")
	unknown, err := Render(cfg, st, testImages, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(content(t, unknown, EnvFile), "PUID") {
		t.Error(".env names an owner although none is known")
	}
	if files.WithPrefix(HomeDir).Hash() != unknown.WithPrefix(HomeDir).Hash() {
		t.Error("the owner changed a mounted file; it belongs in .env only")
	}

	data, err := os.ReadFile("../../docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	edge := content(t, files, EdgeDir+"docker-compose.yml")
	for name, compose := range map[string]string{"home compose": string(data), "edge compose": edge} {
		wantAll(t, name, compose, `PUID: "${HEARTHGATE_PUID:-1000}"`, `PGID: "${HEARTHGATE_PGID:-1000}"`)
	}
}

// The compose defaults must match what ctl renders for the default config,
// or a stack started before the first `ctl apply` would differ from one after.
func TestHomeComposeRangeDefaults(t *testing.T) {
	data, err := os.ReadFile("../../docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`ip_range: "${HEARTHGATE_DMZ_RANGE:-10.210.1.128/25}"`,
		`ip_range: "${HEARTHGATE_MGMT_RANGE:-10.210.2.128/25}"`,
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("docker-compose.yml lacks %s", want)
		}
	}
}

// The example file is what `ctl init` hands new users, so it must always be valid.
// Compose resolves mounts before ctl starts, so a mount that fails when the
// user has no ~/.ssh would abort every command, including `init`. Settings
// that only the end-to-end test needs belong in its override file.
func TestHomeComposeHasNoInstallTraps(t *testing.T) {
	data, err := os.ReadFile("../../docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"create_host_path: false", "host.docker.internal"} {
		if strings.Contains(string(data), bad) {
			t.Errorf("docker-compose.yml contains %q", bad)
		}
	}
}

func TestExampleConfigIsValid(t *testing.T) {
	c, err := config.Parse(ExampleConfig)
	if err != nil {
		t.Fatalf("hearthgate.example.yml does not parse: %v", err)
	}
	if len(c.Publish) != 1 || len(c.Agents) != 1 || c.SSH == "" {
		t.Errorf("example config resolved unexpectedly: %+v", c)
	}
}
