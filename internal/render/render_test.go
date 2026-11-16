package render

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/xrvo/hearthgate/internal/config"
	"github.com/xrvo/hearthgate/internal/keys"
	"github.com/xrvo/hearthgate/internal/state"
)

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
	files, err := Render(cfg, st)
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
	a, err := Render(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Render(cfg, st)
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

	home := content(t, files, HomeDir+"wireguard/wg_confs/wg0.conf")
	wantAll(t, "home wg0.conf", home,
		"Address = 10.210.0.2/32", "PrivateKey = "+st.HomePrivate, "PublicKey = "+edgePub,
		"Endpoint = 203.0.113.5:51820", "AllowedIPs = 10.210.0.1/32", "PersistentKeepalive = 25")
	if strings.Contains(home, st.EdgePrivate) {
		t.Error("home wg0.conf contains the edge private key")
	}

	edge := content(t, files, EdgeDir+"wireguard/wg_confs/wg0.conf")
	wantAll(t, "edge wg0.conf", edge,
		"Address = 10.210.0.1/32", "ListenPort = 51820", "PrivateKey = "+st.EdgePrivate,
		"PublicKey = "+homePub, "AllowedIPs = 10.210.0.2/32")
	if strings.Contains(edge, "Endpoint") {
		t.Error("edge wg0.conf has an Endpoint; home must be the side that dials")
	}

	for _, p := range []string{HomeDir + "wireguard/wg_confs/wg0.conf", EdgeDir + "wireguard/wg_confs/wg0.conf"} {
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
	fw := content(t, files, HomeDir+"wireguard/firewall.sh")
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
	fw := content(t, files, EdgeDir+"wireguard/firewall.sh")
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
	c := content(t, files, HomeDir+"Caddyfile")
	wantAll(t, "Caddyfile", c,
		"default_bind 10.210.0.2", "allow 10.210.0.1/32", "fallback_policy reject",
		"disable_http_challenge", "admin off",
		"photos.example.com {\n\treverse_proxy immich-server:2283\n}",
		"docs.example.com {\n\treverse_proxy paperless:8000\n}")
	if strings.Contains(c, "local_certs") || strings.Contains(c, "staging") {
		t.Errorf("default CA should be production Let's Encrypt:\n%s", c)
	}

	internal, _ := mustRender(t, sample+"tls: {ca: internal, email: me@example.com}\n")
	ci := content(t, internal, HomeDir+"Caddyfile")
	wantAll(t, "internal Caddyfile", ci, "local_certs", "email me@example.com")
	if strings.Contains(ci, "cert_issuer") {
		t.Error("internal CA must not configure ACME")
	}

	staging, _ := mustRender(t, sample+"tls: {ca: letsencrypt-staging}\n")
	wantAll(t, "staging Caddyfile", content(t, staging, HomeDir+"Caddyfile"),
		"dir https://acme-staging-v02.api.letsencrypt.org/directory", "disable_http_challenge")
}

func TestStreamProxies(t *testing.T) {
	files, _ := mustRender(t, sample)

	home := content(t, files, HomeDir+"nginx.conf")
	wantAll(t, "home nginx.conf", home,
		"listen 10.210.2.2:45876;", "proxy_pass 10.210.0.1:45876;",
		"listen 10.210.2.2:18080;", "proxy_pass 10.210.0.1:18080;")

	edge := content(t, files, EdgeDir+"nginx.conf")
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
	edge := content(t, files, EdgeDir+"nginx.conf")
	if strings.Contains(edge, "agent_upstream") || strings.Contains(edge, "resolver") {
		t.Errorf("edge nginx.conf mentions agents when none are configured:\n%s", edge)
	}
	if strings.Contains(content(t, files, HomeDir+"nginx.conf"), "listen") {
		t.Error("home nginx.conf listens when no agents are configured")
	}
}

func TestCustomPorts(t *testing.T) {
	files, _ := mustRender(t, "edge: {address: vps.example.net, https_port: 8443, http_port: 8080, wireguard_port: 51900}\npublish: {a.example.com: app:80}\n")
	wantAll(t, "edge nginx.conf", content(t, files, EdgeDir+"nginx.conf"), "return 301 https://$host:8443$request_uri;")
	wantAll(t, "edge compose", content(t, files, EdgeDir+"docker-compose.yml"),
		`"51900:51820/udp"`, `"8443:443"`, `"8080:80"`, ImageWireGuard, ImageNginx, "name: hearthgate-agents")
	wantAll(t, "home wg0.conf", content(t, files, HomeDir+"wireguard/wg_confs/wg0.conf"), "Endpoint = vps.example.net:51900")
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
	a, _ := Render(cfgA, st)
	b, _ := Render(cfgB, st)

	if envHash(a) == envHash(b) {
		t.Error("home hash did not change when a published target changed")
	}
	// A home-only change must not restart the edge.
	if !bytes.Equal(a[EdgeDir+"docker-compose.yml"].Content, b[EdgeDir+"docker-compose.yml"].Content) {
		t.Error("edge compose changed for a home-only change")
	}
}

// The home stack's compose file is static, so its image pins can drift from
// the ones rendered into the edge bundle unless something checks. Users copy
// the file on its own, so it must also run without a source checkout.
func TestHomeComposeUsesPinnedImages(t *testing.T) {
	data, err := os.ReadFile("../../docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	compose := string(data)
	for _, img := range []string{ImageWireGuard, ImageNginx, ImageCaddy} {
		if !strings.Contains(compose, "image: "+img+"\n") {
			t.Errorf("docker-compose.yml does not use %s", img)
		}
	}
	if strings.Contains(compose, "build:") {
		t.Error("docker-compose.yml needs a source checkout to build ctl")
	}
}

// The example file is what `ctl init` hands new users, so it must always be valid.
func TestExampleConfigIsValid(t *testing.T) {
	c, err := config.Parse(ExampleConfig)
	if err != nil {
		t.Fatalf("hearthgate.example.yml does not parse: %v", err)
	}
	if len(c.Publish) != 1 || len(c.Agents) != 1 || c.SSH == "" {
		t.Errorf("example config resolved unexpectedly: %+v", c)
	}
}
