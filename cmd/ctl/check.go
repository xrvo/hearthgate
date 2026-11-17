package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xrvo/hearthgate/internal/config"
	"github.com/xrvo/hearthgate/internal/render"
	"github.com/xrvo/hearthgate/internal/state"
)

// A handshake older than this means the tunnel is down: WireGuard renews
// every two minutes while the 25 second keepalive is flowing.
const maxHandshakeAge = 3 * time.Minute

type reporter struct {
	app    *app
	failed int
	warned int
}

// warn reports something that will cause trouble but is not broken now.
func (r *reporter) warn(format string, args ...any) {
	r.warned++
	fmt.Fprintf(r.app.out, "  %s  %s\n", r.app.paint(yellow, "warn"), fmt.Sprintf(format, args...))
}

func (r *reporter) ok(format string, args ...any) {
	fmt.Fprintf(r.app.out, "  %s    %s\n", r.app.paint(green, "ok"), fmt.Sprintf(format, args...))
}

func (r *reporter) fail(format string, args ...any) {
	r.failed++
	fmt.Fprintf(r.app.out, "  %s  %s\n", r.app.paint(red, "FAIL"), fmt.Sprintf(format, args...))
}

// hint lists, under a failure, what usually causes it and how to fix it.
func (r *reporter) hint(lines ...string) {
	for _, l := range lines {
		fmt.Fprintf(r.app.out, "        %s\n", r.app.paint(dim, "- "+l))
	}
}

func (r *reporter) section(title string) {
	fmt.Fprintln(r.app.out, r.app.paint(bold, title))
}

// detail prints the explanation of a failure, indented under it.
func (r *reporter) detail(err error) {
	for _, l := range strings.Split(err.Error(), "\n") {
		fmt.Fprintf(r.app.out, "        %s\n", l)
	}
}

func (r *reporter) skip(format string, args ...any) {
	fmt.Fprintf(r.app.out, "  %s  %s\n", r.app.paint(yellow, "skip"), fmt.Sprintf(format, args...))
}

// reportConfig prints whether the generated files are in step with
// hearthgate.yml. It returns them when they are, and nil otherwise.
func (a *app) reportConfig(r *reporter, cfg *config.Config) render.Files {
	r.section("Configuration")
	r.ok("%s is valid", a.cfgPath)
	st, err := state.Load(a.statePath())
	if err != nil {
		r.fail("%v", err)
		return nil
	}
	files, err := a.renderAll(cfg, st)
	if err != nil {
		r.fail("render: %v", err)
		return nil
	}
	changes, err := a.pending(files)
	if err != nil {
		r.fail("%v", err)
		return nil
	}
	if len(changes) > 0 {
		r.fail("generated files do not match hearthgate.yml (%s)", plural(len(changes), "file differs"))
		r.hint("preview and apply the difference: " + cmdApply)
		return nil
	}
	r.ok("generated files match hearthgate.yml")
	return files
}

// generated is reportConfig without the report.
func (a *app) generated(cfg *config.Config) (render.Files, bool) {
	st, err := state.Load(a.statePath())
	if err != nil {
		return nil, false
	}
	files, err := a.renderAll(cfg, st)
	if err != nil {
		return nil, false
	}
	if changes, err := a.pending(files); err != nil || len(changes) > 0 {
		return nil, false
	}
	return files.WithPrefix(render.EdgeDir), true
}

func (a *app) cmdCheck(ctx context.Context) error {
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	r := &reporter{app: a}
	files := a.reportConfig(r, cfg)

	r.section("DNS")
	a.reportDNS(ctx, r, cfg)

	r.section("Public endpoints")
	for _, p := range cfg.Publish {
		checkTLS(ctx, r, cfg, p.Hostname)
	}

	if cfg.SSH == "" {
		r.section("Edge")
		r.skip("edge.ssh is not set, so the edge cannot be inspected")
	} else {
		var bundle render.Files
		if files != nil {
			bundle = files.WithPrefix(render.EdgeDir)
		}
		if st := a.reportEdge(ctx, r, cfg, bundle); st != nil && st.running["tunnel"] {
			a.probeHome(ctx, r, cfg)
		}
	}

	if r.failed > 0 {
		fmt.Fprintf(a.out, "\n%s\n", a.paint(red, plural(r.failed, "check")+" failed.")+" Fix the first one and run check again: later failures often follow from it.")
		return errReported
	}
	fmt.Fprintf(a.out, "\n%s%s\n", a.paint(green, "All checks passed."), warnings(r))
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
		tlsFailure(r, cfg, hostname, addr, err)
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
		r.hint("something other than this gateway may be answering on "+addr, caddyLogs)
		return
	}
	left := time.Until(leaf.NotAfter)
	days := int(left.Hours() / 24)
	switch {
	case left <= 0:
		r.fail("%s: certificate expired on %s", hostname, leaf.NotAfter.Format(time.DateOnly))
		r.hint("the gateway renews certificates on its own, so something is stopping it", caddyLogs)
	case !verify:
		r.ok("%s: certificate from %q (%s CA, chain not verified), expires in %d days", hostname, leaf.Issuer.CommonName, cfg.TLSCA, days)
	case days < 14:
		r.fail("%s: certificate expires in %d days and has not been renewed", hostname, days)
		r.hint("the gateway renews certificates on its own, so something is stopping it", caddyLogs)
	default:
		r.ok("%s: trusted certificate, expires in %d days", hostname, days)
	}
}

const caddyLogs = "the gateway's log says more: docker compose logs caddy"

// tlsFailure reports a public hostname that could not be reached over TLS,
// telling apart the three places it can break: the edge's public port, the
// path from the edge to home, and the certificate itself.
func tlsFailure(r *reporter, cfg *config.Config, hostname, addr string, err error) {
	var op *net.OpError
	var unknownCA x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var wrongHost x509.HostnameError
	switch {
	case errors.As(err, &op) && op.Op == "dial":
		r.fail("%s: cannot connect to the edge at %s: %v", hostname, addr, op.Err)
		r.hint(
			"if the edge stack is not running, start it: "+pushCommand,
			fmt.Sprintf("open %d/tcp in the VPS firewall and in the provider's security group", cfg.HTTPSPort),
			fmt.Sprintf("check edge.address (%s) in hearthgate.yml", cfg.EdgeAddress),
		)
	case errors.As(err, &unknownCA), errors.As(err, &invalid), errors.As(err, &wrongHost):
		r.fail("%s: the certificate served through %s is not valid: %v", hostname, addr, err)
		r.hint(
			fmt.Sprintf("a certificate is issued the first time a hostname is requested, and only if DNS for %s points at %s", hostname, cfg.EdgeAddress),
			"if you are testing with tls.ca set to letsencrypt-staging or internal, set it in hearthgate.yml so check expects that",
			caddyLogs,
		)
	default:
		r.fail("%s: the edge at %s accepted the connection, but no TLS answer came back from home: %v", hostname, addr, err)
		r.hint(
			"if the home stack is not running, start it: "+cmdUp,
			"if the tunnel check below fails, fix that first",
			fmt.Sprintf("the gateway cannot answer for a hostname it has no certificate for; DNS for %s must point at %s", hostname, cfg.EdgeAddress),
			caddyLogs,
		)
	}
}

// tunnelHints lists why home would not be connected to the edge.
func tunnelHints(r *reporter, cfg *config.Config) {
	r.hint(
		"if the home stack is not running, start it: "+cmdUp+" (`docker compose ps` shows whether the gateway is healthy)",
		fmt.Sprintf("open %d/udp in the VPS firewall and in the provider's security group: home dials out to that port", cfg.WireGuardPort),
		fmt.Sprintf("check edge.address (%s) in hearthgate.yml: it is the address home connects to", cfg.EdgeAddress),
		"after `ctl rotate` both sides need the new keys: "+pushCommand+", then "+cmdUp,
	)
}

// probeHome tries, from inside the edge's tunnel namespace, to open ports on
// the home gateway. Only 443 may answer; anything else open is a hole in the
// home firewall.
func (a *app) probeHome(ctx context.Context, r *reporter, cfg *config.Config) {
	r.section("Home firewall, probed from the edge")
	c := a.client(cfg)
	defer c.Close()

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
	out, err := c.Compose(ctx, probe)
	if err != nil {
		r.fail("could not probe the home gateway from the edge")
		r.detail(err)
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
			r.fail("edge cannot reach the home gateway on 443")
			r.hint("if the tunnel check above failed, fix that first", "otherwise start or restart the home stack: "+cmdUp, caddyLogs)
		case got == "closed":
			r.ok("home port %d is closed to the edge", p)
		default:
			r.fail("home port %d is OPEN to the edge; the home firewall is not in effect", p)
			r.hint("recreate the gateway so its firewall loads again: "+cmdUp+" --force-recreate",
				"if the port is still open after that, treat it as a security bug and report it privately (see SECURITY.md)")
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
