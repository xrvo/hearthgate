// Package config loads and validates hearthgate.yml.
//
// Every value that ends up in a generated proxy config, firewall script or
// remote shell command is validated here against a strict pattern, so the
// renderers can treat a *Config as safe to interpolate.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Defaults for optional settings.
const (
	DefaultTunnelSubnet  = "10.210.0.0/30"
	DefaultDMZSubnet     = "10.210.1.0/24"
	DefaultMgmtSubnet    = "10.210.2.0/24"
	DefaultAgentsSubnet  = "10.210.3.0/24"
	DefaultWireGuardPort = 51820
	DefaultHTTPSPort     = 443
	DefaultHTTPPort      = 80
	DefaultSSHPort       = 22
	DefaultEdgeDir       = "hearthgate"

	CALetsEncrypt        = "letsencrypt"
	CALetsEncryptStaging = "letsencrypt-staging"
	CAInternal           = "internal"
)

// Target is a container name and port on a Docker network.
type Target struct {
	Host string
	Port int
}

func (t Target) String() string { return t.Host + ":" + strconv.Itoa(t.Port) }

// Published maps a public hostname to a home container.
type Published struct {
	Hostname string
	Target   Target
}

// Agent is an edge container that home hubs may connect to.
// Listen is the port used on the tunnel and on the home gateway.
type Agent struct {
	Name   string
	Target Target
	Listen int
}

// Config is the validated configuration with all defaults applied.
type Config struct {
	EdgeAddress   string
	SSH           string
	SSHPort       int
	EdgeDir       string
	WireGuardPort int
	HTTPSPort     int
	HTTPPort      int

	Publish []Published // sorted by hostname
	Agents  []Agent     // sorted by name

	TLSCA    string
	TLSEmail string

	TunnelSubnet netip.Prefix
	EdgeIP       netip.Addr // edge end of the tunnel
	HomeIP       netip.Addr // home end of the tunnel

	DMZSubnet    netip.Prefix
	DMZIP        netip.Addr // gateway address on hearthgate-dmz
	MgmtSubnet   netip.Prefix
	MgmtIP       netip.Addr // gateway address on hearthgate-mgmt
	AgentsSubnet netip.Prefix
}

// Endpoint is the WireGuard endpoint the home gateway dials.
func (c *Config) Endpoint() string {
	return net.JoinHostPort(c.EdgeAddress, strconv.Itoa(c.WireGuardPort))
}

type rawConfig struct {
	Edge struct {
		Address       string `yaml:"address"`
		SSH           string `yaml:"ssh"`
		SSHPort       int    `yaml:"ssh_port"`
		Dir           string `yaml:"dir"`
		WireGuardPort int    `yaml:"wireguard_port"`
		HTTPSPort     int    `yaml:"https_port"`
		HTTPPort      int    `yaml:"http_port"`
	} `yaml:"edge"`
	Publish map[string]string   `yaml:"publish"`
	Agents  map[string]rawAgent `yaml:"agents"`
	TLS     struct {
		CA    string `yaml:"ca"`
		Email string `yaml:"email"`
	} `yaml:"tls"`
	Tunnel struct {
		Subnet string `yaml:"subnet"`
	} `yaml:"tunnel"`
	Networks struct {
		DMZ    string `yaml:"dmz"`
		Mgmt   string `yaml:"mgmt"`
		Agents string `yaml:"agents"`
	} `yaml:"networks"`
}

// rawAgent accepts either "container:port" or {target: ..., listen: ...}.
type rawAgent struct {
	Target string
	Listen int
}

func (a *rawAgent) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		a.Target = n.Value
		return nil
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, val := n.Content[i], n.Content[i+1]
			switch key.Value {
			case "target":
				a.Target = val.Value
			case "listen":
				if err := val.Decode(&a.Listen); err != nil {
					return fmt.Errorf("line %d: listen must be a port number", val.Line)
				}
			default:
				return fmt.Errorf("line %d: unknown agent field %q (expected target, listen)", key.Line, key.Value)
			}
		}
		return nil
	}
	return fmt.Errorf("line %d: agent must be \"container:port\" or a mapping with target and listen", n.Line)
}

var (
	reHostname  = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)
	reAddress   = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)
	reContainer = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)
	reAgentName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
	reSSHUser   = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}$`)
	reDir       = regexp.MustCompile(`^[a-zA-Z0-9_/.-]+$`)
	reEmail     = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
)

// Parse validates the YAML document and returns the resolved configuration.
// All problems found are reported together.
func Parse(data []byte) (*Config, error) {
	var raw rawConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return nil, yamlError(err)
	}

	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	c := &Config{
		EdgeAddress:   raw.Edge.Address,
		SSH:           raw.Edge.SSH,
		SSHPort:       orDefault(raw.Edge.SSHPort, DefaultSSHPort),
		EdgeDir:       raw.Edge.Dir,
		WireGuardPort: orDefault(raw.Edge.WireGuardPort, DefaultWireGuardPort),
		HTTPSPort:     orDefault(raw.Edge.HTTPSPort, DefaultHTTPSPort),
		HTTPPort:      orDefault(raw.Edge.HTTPPort, DefaultHTTPPort),
		TLSCA:         raw.TLS.CA,
		TLSEmail:      raw.TLS.Email,
	}
	if c.EdgeDir == "" {
		c.EdgeDir = DefaultEdgeDir
	}
	if c.TLSCA == "" {
		c.TLSCA = CALetsEncrypt
	}

	// edge
	switch {
	case c.EdgeAddress == "":
		fail("edge.address is required (public IP or hostname of the VPS)")
	case !validAddress(c.EdgeAddress):
		fail("edge.address %q is not a valid IP address or hostname", c.EdgeAddress)
	}
	if c.SSH != "" {
		user, host, ok := strings.Cut(c.SSH, "@")
		if !ok || !reSSHUser.MatchString(user) || !validAddress(host) {
			fail("edge.ssh %q must look like user@host", c.SSH)
		}
	}
	if !reDir.MatchString(c.EdgeDir) || strings.Contains(c.EdgeDir, "..") || strings.HasPrefix(c.EdgeDir, "-") {
		fail("edge.dir %q may only contain letters, digits, '/', '_', '.', '-' and no '..'", c.EdgeDir)
	}
	for name, p := range map[string]int{
		"edge.ssh_port": c.SSHPort, "edge.wireguard_port": c.WireGuardPort,
		"edge.https_port": c.HTTPSPort, "edge.http_port": c.HTTPPort,
	} {
		if !validPort(p) {
			fail("%s %d is not a valid port", name, p)
		}
	}
	if c.HTTPSPort == c.HTTPPort {
		fail("edge.https_port and edge.http_port must differ")
	}

	// tls
	switch c.TLSCA {
	case CALetsEncrypt, CALetsEncryptStaging, CAInternal:
	default:
		fail("tls.ca %q must be one of %s, %s, %s", c.TLSCA, CALetsEncrypt, CALetsEncryptStaging, CAInternal)
	}
	if c.TLSEmail != "" && !reEmail.MatchString(c.TLSEmail) {
		fail("tls.email %q is not a valid email address", c.TLSEmail)
	}

	// publish
	if len(raw.Publish) == 0 {
		fail("publish needs at least one entry (public hostname: container:port)")
	}
	seenHost := map[string]bool{}
	for host, target := range raw.Publish {
		h := strings.ToLower(host)
		if !reHostname.MatchString(h) || len(h) > 253 {
			fail("publish: %q is not a valid hostname (wildcards are not supported)", host)
			continue
		}
		if seenHost[h] {
			fail("publish: hostname %q is listed twice", h)
			continue
		}
		seenHost[h] = true
		t, err := parseTarget(target)
		if err != nil {
			fail("publish.%s: %v", host, err)
			continue
		}
		c.Publish = append(c.Publish, Published{Hostname: h, Target: t})
	}
	sort.Slice(c.Publish, func(i, j int) bool { return c.Publish[i].Hostname < c.Publish[j].Hostname })

	// agents
	// Ports the gateway or edge already use inside their network namespace.
	reserved := map[int]string{80: "HTTP", 443: "HTTPS", 2019: "the Caddy admin port"}
	usedListen := map[int]string{}
	for name, ra := range raw.Agents {
		if !reAgentName.MatchString(name) {
			fail("agents: name %q must be lowercase letters, digits and '-'", name)
			continue
		}
		t, err := parseTarget(ra.Target)
		if err != nil {
			fail("agents.%s: %v", name, err)
			continue
		}
		listen := orDefault(ra.Listen, t.Port)
		if !validPort(listen) {
			fail("agents.%s: listen %d is not a valid port", name, listen)
			continue
		}
		if what, ok := reserved[listen]; ok {
			fail("agents.%s: port %d is reserved for %s; set a different one with {target: %s, listen: <port>}", name, listen, what, t)
			continue
		}
		if other, ok := usedListen[listen]; ok {
			fail("agents.%s: port %d is already used by agent %q; set a different one with {target: %s, listen: <port>}", name, listen, other, t)
			continue
		}
		usedListen[listen] = name
		c.Agents = append(c.Agents, Agent{Name: name, Target: t, Listen: listen})
	}
	sort.Slice(c.Agents, func(i, j int) bool { return c.Agents[i].Name < c.Agents[j].Name })

	// subnets
	subnet := func(key, val, def string, maxBits int) netip.Prefix {
		if val == "" {
			val = def
		}
		p, err := netip.ParsePrefix(val)
		if err != nil || !p.Addr().Is4() {
			fail("%s %q is not an IPv4 subnet in CIDR form", key, val)
			return netip.Prefix{}
		}
		if p.Bits() > maxBits {
			fail("%s %q is too small; use /%d or larger", key, val, maxBits)
			return netip.Prefix{}
		}
		return p.Masked()
	}
	c.TunnelSubnet = subnet("tunnel.subnet", raw.Tunnel.Subnet, DefaultTunnelSubnet, 30)
	c.DMZSubnet = subnet("networks.dmz", raw.Networks.DMZ, DefaultDMZSubnet, 29)
	c.MgmtSubnet = subnet("networks.mgmt", raw.Networks.Mgmt, DefaultMgmtSubnet, 29)
	c.AgentsSubnet = subnet("networks.agents", raw.Networks.Agents, DefaultAgentsSubnet, 29)

	named := []struct {
		name string
		p    netip.Prefix
	}{
		{"tunnel.subnet", c.TunnelSubnet}, {"networks.dmz", c.DMZSubnet},
		{"networks.mgmt", c.MgmtSubnet}, {"networks.agents", c.AgentsSubnet},
	}
	for i := range named {
		for j := i + 1; j < len(named); j++ {
			if named[i].p.IsValid() && named[j].p.IsValid() && named[i].p.Overlaps(named[j].p) {
				fail("%s (%s) overlaps %s (%s)", named[i].name, named[i].p, named[j].name, named[j].p)
			}
		}
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	// Tunnel: first two host addresses. Docker networks: .1 is Docker's own
	// bridge gateway, so the Hearthgate gateway takes .2.
	c.EdgeIP = c.TunnelSubnet.Addr().Next()
	c.HomeIP = c.EdgeIP.Next()
	c.DMZIP = c.DMZSubnet.Addr().Next().Next()
	c.MgmtIP = c.MgmtSubnet.Addr().Next().Next()
	return c, nil
}

func orDefault(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }

func validAddress(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	return reAddress.MatchString(s) && !strings.Contains(s, "..")
}

func parseTarget(s string) (Target, error) {
	host, portStr, ok := strings.Cut(s, ":")
	if !ok || !reContainer.MatchString(host) {
		return Target{}, fmt.Errorf("%q must look like container:port", s)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || !validPort(port) {
		return Target{}, fmt.Errorf("%q has an invalid port", s)
	}
	return Target{Host: host, Port: port}, nil
}
