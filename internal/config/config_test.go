package config

import (
	"strings"
	"testing"
)

const minimal = `
edge:
  address: 203.0.113.5
publish:
  photos.example.com: immich-server:2283
`

func TestParseDefaults(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Endpoint(); got != "203.0.113.5:51820" {
		t.Errorf("Endpoint = %q", got)
	}
	if c.EdgeIP.String() != "10.210.0.1" || c.HomeIP.String() != "10.210.0.2" {
		t.Errorf("tunnel IPs = %s, %s", c.EdgeIP, c.HomeIP)
	}
	if c.DMZIP.String() != "10.210.1.2" || c.MgmtIP.String() != "10.210.2.2" {
		t.Errorf("gateway IPs = %s, %s", c.DMZIP, c.MgmtIP)
	}
	if c.TLSCA != CALetsEncrypt || c.HTTPSPort != 443 || c.HTTPPort != 80 || c.EdgeDir != "hearthgate" {
		t.Errorf("unexpected defaults: %+v", c)
	}
	if len(c.Publish) != 1 || c.Publish[0].Target.String() != "immich-server:2283" {
		t.Errorf("publish = %+v", c.Publish)
	}
}

func TestParseAgentsForms(t *testing.T) {
	c, err := Parse([]byte(minimal + `
agents:
  beszel: beszel-agent:45876
  web:
    target: some-agent:80
    listen: 18080
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Agents) != 2 {
		t.Fatalf("agents = %+v", c.Agents)
	}
	if a := c.Agents[0]; a.Name != "beszel" || a.Listen != 45876 {
		t.Errorf("short form = %+v", a)
	}
	if a := c.Agents[1]; a.Name != "web" || a.Listen != 18080 || a.Target.Port != 80 {
		t.Errorf("long form = %+v", a)
	}
}

func TestParseIPv6Endpoint(t *testing.T) {
	c, err := Parse([]byte("edge: {address: '2001:db8::5'}\npublish: {a.example.com: app:80}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Endpoint(); got != "[2001:db8::5]:51820" {
		t.Errorf("Endpoint = %q", got)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]struct{ yaml, want string }{
		"missing address":   {"publish: {a.example.com: app:80}", "edge.address is required"},
		"no publish":        {"edge: {address: 1.2.3.4}", "publish needs at least one entry"},
		"unknown key":       {minimal + "bogus: 1\n", "field bogus not found"},
		"wildcard host":     {"edge: {address: 1.2.3.4}\npublish: {'*.example.com': app:80}", "not a valid hostname"},
		"shell in address":  {"edge: {address: '1.2.3.4; rm -rf /'}\npublish: {a.example.com: app:80}", "edge.address"},
		"shell in target":   {"edge: {address: 1.2.3.4}\npublish: {a.example.com: 'app$(id):80'}", "container:port"},
		"newline in target": {"edge: {address: 1.2.3.4}\npublish: {a.example.com: \"app:80\\n}\"}", "invalid port"},
		"bad port":          {"edge: {address: 1.2.3.4}\npublish: {a.example.com: app:99999}", "invalid port"},
		"bad ssh":           {"edge: {address: 1.2.3.4, ssh: 'root@host -oProxyCommand=x'}\npublish: {a.example.com: app:80}", "user@host"},
		"dir traversal":     {"edge: {address: 1.2.3.4, dir: ../etc}\npublish: {a.example.com: app:80}", "edge.dir"},
		"reserved port":     {minimal + "agents: {web: agent:80}\n", "reserved for HTTP"},
		"duplicate port":    {minimal + "agents: {a: one:7000, b: two:7000}\n", "already used by agent"},
		"bad agent field":   {minimal + "agents: {a: {target: one:7000, port: 1}}\n", "unknown agent field"},
		"bad ca":            {minimal + "tls: {ca: zerossl}\n", "tls.ca"},
		"overlap":           {minimal + "networks: {dmz: 10.210.0.0/24}\n", "overlaps"},
		"tunnel too small":  {minimal + "tunnel: {subnet: 10.9.9.0/31}\n", "too small"},
		"ipv6 subnet":       {minimal + "tunnel: {subnet: 'fd00::/64'}\n", "not an IPv4 subnet"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestParseReportsAllErrors(t *testing.T) {
	_, err := Parse([]byte("edge: {address: ''}\npublish: {bad_host: app:80}\ntls: {ca: nope}\n"))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"edge.address", "bad_host", "tls.ca"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error is missing %q:\n%v", want, err)
		}
	}
}
