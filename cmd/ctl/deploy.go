package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xrvo/hearthgate/internal/config"
	"github.com/xrvo/hearthgate/internal/render"
	"github.com/xrvo/hearthgate/internal/state"
)

const cmdDeploy = "docker compose run --rm ctl deploy"

// Compose releases older than this cannot read the stacks' compose files.
var minCompose = [2]int{2, 17}

// lookupHost resolves a name. Tests replace it.
var lookupHost = net.DefaultResolver.LookupHost

// cmdDeploy brings the edge in line with hearthgate.yml in one go: it checks
// the VPS, applies pending changes, pushes, waits for home to connect and
// runs the checks. It cannot start the home gateway, which runs beside it.
func (a *app) cmdDeploy(ctx context.Context, yes bool, wait time.Duration) error {
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	if cfg.SSH == "" {
		return fmt.Errorf("deploy needs edge.ssh, and it is not set.\nSet it in hearthgate.yml, or do the steps yourself: `ctl apply`, then\n  %s", bundleCommand(cfg))
	}
	st, err := state.Load(a.statePath())
	if err != nil {
		return err
	}
	files, err := a.renderAll(cfg, st)
	if err != nil {
		return err
	}

	r := &reporter{app: a}
	r.section("Before deploying")
	a.reportDNS(ctx, r, cfg)
	a.preflightEdge(ctx, r, cfg)
	if r.failed > 0 {
		fmt.Fprintf(a.out, "\n%s Nothing was changed. Fix the above and run deploy again.\n", a.paint(red, "Deploy stopped."))
		return errReported
	}
	fmt.Fprintln(a.out)

	changes, err := a.stage(cfg, st, files, yes, false)
	if err != nil {
		return err
	}
	if len(changes) == 0 {
		fmt.Fprintln(a.out, "Generated files already match hearthgate.yml.")
	}
	if err := a.push(ctx, cfg, files); err != nil {
		if len(changes) > 0 {
			return fmt.Errorf("%w\n\n%s", err, afterFailedPush(false))
		}
		return err
	}

	if touches(changes, render.HomeDir) || touches(changes, render.EnvFile) {
		fmt.Fprintln(a.out, "\nThe edge is updated. The home gateway still runs the previous files, so the result")
		fmt.Fprintln(a.out, "cannot be verified until it restarts.")
		a.next(step{cmdUp, "restart the home gateway with the new files"}, step{cmdCheck, "verify the result"})
		return nil
	}

	fmt.Fprintf(a.out, "\nWaiting for home to connect to the edge (up to %s) ...\n", wait.Round(time.Second))
	if !a.waitForTunnel(ctx, cfg, wait) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		fmt.Fprintf(a.out, "%s The edge is installed and running, so this is about the home side or the path to it:\n", a.paint(red, "Home has not connected."))
		tunnelHints(r, cfg)
		a.next(step{cmdUp, "start the home gateway, if it is not running"}, step{cmdCheck, "verify once it is up"})
		return errReported
	}
	fmt.Fprintf(a.out, "Home is connected.\n\n")
	return a.cmdCheck(ctx)
}

// waitForTunnel polls the edge until it has a fresh handshake with home.
func (a *app) waitForTunnel(ctx context.Context, cfg *config.Config, wait time.Duration) bool {
	c := a.client(cfg)
	defer c.Close()
	deadline := time.Now().Add(wait)
	for {
		if st, err := a.edgeState(ctx, c, cfg, nil); err == nil {
			if age, err := handshakeAge(st.handshake); err == nil && age <= maxHandshakeAge {
				return true
			}
		}
		if ctx.Err() != nil || !time.Now().Add(3*time.Second).Before(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(3 * time.Second):
		}
	}
}

// reportDNS checks that each published hostname resolves to the edge. A
// mismatch is a warning, not a failure: DNS may be about to change, and
// tls.ca "internal" is there for trying things out without it.
func (a *app) reportDNS(ctx context.Context, r *reporter, cfg *config.Config) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	edge := map[string]bool{}
	if ip, err := netip.ParseAddr(cfg.EdgeAddress); err == nil {
		edge[ip.String()] = true
	} else {
		addrs, err := lookupHost(ctx, cfg.EdgeAddress)
		if err != nil || len(addrs) == 0 {
			r.warn("DNS: edge.address %s does not resolve from here, so hostnames cannot be compared with it", cfg.EdgeAddress)
			return
		}
		for _, addr := range addrs {
			edge[canonical(addr)] = true
		}
	}
	edgeList := keys(edge)
	edgeHasV6 := false
	for _, e := range edgeList {
		edgeHasV6 = edgeHasV6 || strings.Contains(e, ":")
	}
	certs := "a certificate cannot be issued for it until it does"
	if cfg.TLSCA == config.CAInternal {
		certs = "visitors cannot reach it by name until it does"
	}

	for _, p := range cfg.Publish {
		addrs, err := lookupHost(ctx, p.Hostname)
		if err != nil || len(addrs) == 0 {
			r.warn("DNS: %s does not resolve yet; %s", p.Hostname, certs)
			r.hint(fmt.Sprintf("create a DNS record for %s pointing at %s", p.Hostname, strings.Join(edgeList, " or ")))
			continue
		}
		var stray []string
		strayV6 := false
		for _, addr := range addrs {
			if c := canonical(addr); !edge[c] {
				stray = append(stray, c)
				strayV6 = strayV6 || strings.Contains(c, ":")
			}
		}
		if len(stray) == 0 {
			r.ok("DNS: %s points at the edge", p.Hostname)
			continue
		}
		r.warn("DNS: %s resolves to %s, which is not the edge (%s)", p.Hostname, strings.Join(stray, ", "), strings.Join(edgeList, ", "))
		hints := []string{
			fmt.Sprintf("point its DNS record at %s; a change can take a while to spread", strings.Join(edgeList, " or ")),
			"a proxying CDN in front (such as Cloudflare's orange cloud) will not work: TLS has to end at home",
		}
		if strayV6 && !edgeHasV6 {
			hints = append(hints, "remove its AAAA (IPv6) record: certificate authorities prefer IPv6, and that address is not the edge")
		}
		r.hint(hints...)
	}
}

func canonical(addr string) string {
	if ip, err := netip.ParseAddr(addr); err == nil {
		return ip.Unmap().String()
	}
	return addr
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// preflight is what one query of the VPS returns before a deploy.
type preflight struct {
	docker    string
	compose   string
	running   map[string]bool
	listening map[string]bool // "tcp:443"
	canList   bool            // the VPS has a tool that lists listening ports
}

func parsePreflight(out string) *preflight {
	p := &preflight{running: map[string]bool{}, listening: map[string]bool{}}
	section := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "::") {
			section = line
			p.canList = p.canList || section == "::listen"
			continue
		}
		if line == "" {
			continue
		}
		switch section {
		case "::docker":
			p.docker = line
		case "::compose":
			p.compose = line
		case "::running":
			p.running[line] = true
		case "::listen":
			// "tcp 0.0.0.0:443", "udp [::]:51820", "tcp *:80"
			if f := strings.Fields(line); len(f) == 2 {
				if i := strings.LastIndex(f[1], ":"); i >= 0 {
					p.listening[f[0]+":"+f[1][i+1:]] = true
				}
			}
		}
	}
	return p
}

// composeTooOld reports whether a `docker compose version --short` string is
// a release before minCompose. Versions it cannot read are let through.
func composeTooOld(v string) bool {
	parts := strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return major < minCompose[0] || (major == minCompose[0] && minor < minCompose[1])
}

// preflightEdge checks, before anything is sent, that the VPS can run the
// edge: ssh works, Docker and a recent Compose answer, and nothing else
// holds the public ports.
func (a *app) preflightEdge(ctx context.Context, r *reporter, cfg *config.Config) {
	const script = `echo ::docker
docker version --format '{{.Server.Version}}' || exit $?
echo ::compose
docker compose version --short || exit $?
echo ::running
if cd %s 2>/dev/null && test -f docker-compose.yml; then docker compose ps --services --status running 2>/dev/null; fi
if command -v ss >/dev/null 2>&1; then
	echo ::listen
	ss -H -ltn | awk '{print "tcp", $4}'
	ss -H -lun | awk '{print "udp", $4}'
elif command -v netstat >/dev/null 2>&1; then
	echo ::listen
	netstat -ltn | awk '$1 ~ /^tcp/ {print "tcp", $4}'
	netstat -lun | awk '$1 ~ /^udp/ {print "udp", $4}'
fi
exit 0`
	c := a.client(cfg)
	defer c.Close()
	out, err := c.Run(ctx, fmt.Sprintf(script, cfg.EdgeDir), nil)
	if err != nil {
		r.fail("the VPS is not ready (%s)", cfg.SSH)
		r.detail(err)
		return
	}
	p := parsePreflight(string(out))
	r.ok("ssh to %s works", cfg.SSH)
	if composeTooOld(p.compose) {
		r.fail("Compose %s on the VPS is too old; Hearthgate needs %d.%d or newer", p.compose, minCompose[0], minCompose[1])
		r.hint("update it there: sudo apt-get update && sudo apt-get install docker-compose-plugin, or see https://docs.docker.com/compose/install/linux/")
	} else {
		r.ok("Docker %s and Compose %s on the VPS", p.docker, p.compose)
	}

	want := []struct {
		proto string
		port  int
	}{{"tcp", cfg.HTTPSPort}, {"tcp", cfg.HTTPPort}, {"udp", cfg.WireGuardPort}}
	var names, busy []string
	for _, w := range want {
		name := fmt.Sprintf("%d/%s", w.port, w.proto)
		names = append(names, name)
		if p.listening[fmt.Sprintf("%s:%d", w.proto, w.port)] {
			busy = append(busy, name)
		}
	}
	switch {
	case p.running["tunnel"]:
		r.ok("the edge is already running there and holds its ports")
	case !p.canList:
		r.skip("could not list the ports in use on the VPS (no ss or netstat there)")
	case len(busy) > 0:
		r.fail("%s already in use on the VPS by another program: %s", plural(len(busy), "port"), strings.Join(busy, ", "))
		r.hint(
			"find what holds it, on the VPS: sudo ss -ltnup | grep -E ':("+portPattern(busy)+") '",
			"it is often a web server (nginx, Apache, Caddy) or another container (docker ps); stop or move it",
		)
	default:
		r.ok("ports %s are free on the VPS", strings.Join(names, ", "))
	}
}

func portPattern(busy []string) string {
	var ports []string
	for _, b := range busy {
		port, _, _ := strings.Cut(b, "/")
		ports = append(ports, port)
	}
	return strings.Join(ports, "|")
}

// stage previews pending changes to the generated files and, once confirmed,
// writes them. It returns what changed; nothing pending is not an error.
func (a *app) stage(cfg *config.Config, st *state.State, files render.Files, yes, saveState bool) ([]change, error) {
	changes, err := a.pending(files)
	if err != nil || len(changes) == 0 {
		return nil, err
	}
	a.printChanges(changes)
	for _, note := range networkNotes(changes) {
		fmt.Fprintf(a.out, "%s\n\n", note)
	}
	if !yes {
		if ok, err := a.confirmOrYes("Apply these changes?"); err != nil {
			return nil, fmt.Errorf("%w; nothing was written", err)
		} else if !ok {
			return nil, errCancelled
		}
	}
	if saveState {
		if err := st.Save(a.statePath()); err != nil {
			return nil, err
		}
	}
	if err := a.write(files); err != nil {
		return nil, err
	}
	fmt.Fprintf(a.out, "Wrote %s under generated/.\n", plural(len(changes), "file"))
	return changes, nil
}
