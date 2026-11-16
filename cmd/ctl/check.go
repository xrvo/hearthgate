package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xrvo/hearthgate/internal/config"
	"github.com/xrvo/hearthgate/internal/state"
)

// A handshake older than this means the tunnel is down: WireGuard renews
// every two minutes while the 25 second keepalive is flowing.
const maxHandshakeAge = 3 * time.Minute

type reporter struct {
	app    *app
	failed int
}

func (r *reporter) ok(format string, args ...any) {
	fmt.Fprintf(r.app.out, "  ok    %s\n", fmt.Sprintf(format, args...))
}

func (r *reporter) fail(format string, args ...any) {
	r.failed++
	fmt.Fprintf(r.app.out, "  FAIL  %s\n", fmt.Sprintf(format, args...))
}

func (r *reporter) skip(format string, args ...any) {
	fmt.Fprintf(r.app.out, "  skip  %s\n", fmt.Sprintf(format, args...))
}

func (a *app) cmdCheck(ctx context.Context) error {
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	r := &reporter{app: a}

	fmt.Fprintln(a.out, "Configuration")
	r.ok("%s is valid", a.cfgPath)
	st, err := state.Load(a.statePath())
	if err != nil {
		r.fail("%v", err)
	} else if files, err := a.renderAll(cfg, st); err != nil {
		r.fail("render: %v", err)
	} else if changes, err := a.pending(files); err != nil {
		r.fail("%v", err)
	} else if len(changes) > 0 {
		r.fail("generated files do not match hearthgate.yml (%d differ); run `ctl apply`", len(changes))
	} else {
		r.ok("generated files match hearthgate.yml")
	}

	fmt.Fprintln(a.out, "Public endpoints")
	for _, p := range cfg.Publish {
		checkTLS(ctx, r, cfg, p.Hostname)
	}

	fmt.Fprintln(a.out, "Tunnel and firewall, seen from the edge")
	if cfg.SSH == "" {
		r.skip("edge.ssh is not set, so the edge cannot be inspected")
	} else {
		a.checkEdge(ctx, r, cfg)
	}

	if r.failed > 0 {
		fmt.Fprintf(a.out, "\n%d check(s) failed.\n", r.failed)
		return errReported
	}
	fmt.Fprintln(a.out, "\nAll checks passed.")
	return nil
}

// checkTLS connects to the edge's public HTTPS port the way a browser would
// and inspects the certificate the home gateway presents through it.
func checkTLS(ctx context.Context, r *reporter, cfg *config.Config, hostname string) {
	addr := net.JoinHostPort(cfg.EdgeAddress, strconv.Itoa(cfg.HTTPSPort))
	// Only the production CA chains to a root this machine trusts.
	verify := cfg.TLSCA == config.CALetsEncrypt
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config:    &tls.Config{ServerName: hostname, InsecureSkipVerify: !verify},
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		r.fail("%s: no valid TLS connection through %s: %v", hostname, addr, err)
		return
	}
	defer conn.Close()

	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		r.fail("%s: no certificate presented", hostname)
		return
	}
	leaf := certs[0]
	if err := leaf.VerifyHostname(hostname); err != nil {
		r.fail("%s: certificate is for a different name: %v", hostname, err)
		return
	}
	left := time.Until(leaf.NotAfter)
	days := int(left.Hours() / 24)
	switch {
	case left <= 0:
		r.fail("%s: certificate expired on %s", hostname, leaf.NotAfter.Format(time.DateOnly))
	case !verify:
		r.ok("%s: certificate from %q (%s CA, chain not verified), expires in %d days", hostname, leaf.Issuer.CommonName, cfg.TLSCA, days)
	case days < 14:
		r.fail("%s: certificate expires in %d days and has not been renewed", hostname, days)
	default:
		r.ok("%s: trusted certificate, expires in %d days", hostname, days)
	}
}

// checkEdge asks the edge for the handshake age, then tries from inside the
// edge's tunnel namespace to open ports on the home gateway. Only 443 may
// answer; anything else open is a hole in the home firewall.
func (a *app) checkEdge(ctx context.Context, r *reporter, cfg *config.Config) {
	c := a.client(cfg)
	defer c.Close()

	out, err := c.Compose(ctx, `exec -T tunnel sh -c "wg show wg0 latest-handshakes; echo now; date +%s"`)
	if err != nil {
		r.fail("could not query the edge tunnel: %v", err)
		return
	}
	if age, err := handshakeAge(string(out)); err != nil {
		r.fail("tunnel: %v", err)
	} else if age > maxHandshakeAge {
		r.fail("tunnel: last handshake was %s ago; home is not connected", age.Round(time.Second))
	} else {
		r.ok("tunnel: last handshake %s ago", age.Round(time.Second))
	}

	closed := map[int]bool{22: true, 53: true, 80: true, 2019: true}
	for _, ag := range cfg.Agents {
		closed[ag.Listen] = true
	}
	ports := []int{443}
	for p := range closed {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	list := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(ports)), " "), "[]")

	probe := fmt.Sprintf(`exec -T tunnel sh -c 'for p in %s; do if nc -z -w 3 %s $p >/dev/null 2>&1; then echo "$p open"; else echo "$p closed"; fi; done'`, list, cfg.HomeIP)
	out, err = c.Compose(ctx, probe)
	if err != nil {
		r.fail("could not probe the home gateway from the edge: %v", err)
		return
	}
	results := parseProbe(string(out))
	for _, p := range ports {
		got, seen := results[p]
		switch {
		case !seen:
			r.fail("port %d: no probe result", p)
		case p == 443 && got == "open":
			r.ok("edge reaches the home gateway on 443")
		case p == 443:
			r.fail("edge cannot reach the home gateway on 443; is the home stack running?")
		case got == "closed":
			r.ok("home port %d is closed to the edge", p)
		default:
			r.fail("home port %d is OPEN to the edge; the home firewall is not in effect", p)
		}
	}
}

// handshakeAge parses the output of `wg show wg0 latest-handshakes`, followed
// by a line "now" and the edge's current Unix time.
func handshakeAge(out string) (time.Duration, error) {
	var last, now int64
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i, line := range lines {
		fields := strings.Fields(line)
		switch {
		case len(fields) == 2 && i == 0:
			last, _ = strconv.ParseInt(fields[1], 10, 64)
		case len(fields) == 1 && i > 0 && lines[i-1] == "now":
			now, _ = strconv.ParseInt(fields[0], 10, 64)
		}
	}
	if now == 0 {
		return 0, fmt.Errorf("unexpected output from the edge: %q", out)
	}
	if last == 0 {
		return 0, fmt.Errorf("home has never connected")
	}
	return time.Duration(now-last) * time.Second, nil
}

func parseProbe(out string) map[int]string {
	results := map[int]string{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if p, err := strconv.Atoi(fields[0]); err == nil {
			results[p] = fields[1]
		}
	}
	return results
}
