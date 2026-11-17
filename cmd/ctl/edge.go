package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xrvo/hearthgate/internal/config"
	"github.com/xrvo/hearthgate/internal/remote"
	"github.com/xrvo/hearthgate/internal/render"
)

// The services of the edge stack, as named in its compose file.
var edgeServices = []string{"tunnel", "proxy"}

const cmdEdgeUp = "docker compose run --rm ctl edge up"

const edgeUsage = `Usage: ctl edge <command> [flags]

Commands:
  up        Start the edge stack as it is installed on the VPS
  down      Stop the edge stack; published sites go offline. Nothing is deleted
  restart   Restart the edge stack
  status    Show whether the edge is running, connected and up to date
  logs      Show the edge's logs. Flags: -f to follow, -tail N; optionally
            name one service: tunnel or proxy
`

type edgeOpts struct {
	sub     string
	service string
	yes     bool
	follow  bool
	tail    int
}

func (o edgeOpts) validate() error {
	switch o.sub {
	case "up", "down", "restart", "status":
		if o.service != "" {
			return fmt.Errorf("unexpected argument %q", o.service)
		}
	case "logs":
		if o.service != "" && o.service != "tunnel" && o.service != "proxy" {
			return fmt.Errorf("unknown service %q: the edge runs tunnel and proxy", o.service)
		}
		if o.tail < 0 || o.tail > 100000 {
			return fmt.Errorf("-tail %d is out of range", o.tail)
		}
	case "":
		return errors.New("edge needs a command")
	default:
		return fmt.Errorf("unknown edge command %q", o.sub)
	}
	return nil
}

func (a *app) cmdEdge(ctx context.Context, o edgeOpts) error {
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	if cfg.SSH == "" {
		return fmt.Errorf("edge.ssh is not set, so ctl cannot reach the edge.\nSet it in hearthgate.yml, or run `docker compose` yourself in ~/%s on the VPS", cfg.EdgeDir)
	}
	if o.sub == "status" {
		r := &reporter{app: a}
		a.reportEdge(ctx, r, cfg, a.currentBundle(cfg))
		return a.verdict(r)
	}

	c := a.client(cfg)
	defer c.Close()
	// compose runs one compose command on the edge, showing its output as it arrives.
	compose := func(what, args string) error {
		fmt.Fprintf(a.out, "%s on %s ...\n", what, cfg.SSH)
		return c.ComposeStream(ctx, args, func(line string) {
			fmt.Fprintf(a.out, "  %s %s\n", a.paint(dim, "edge |"), line)
		})
	}

	switch o.sub {
	case "up":
		if err := compose("Starting the edge stack", "up -d --remove-orphans"); err != nil {
			return err
		}
		fmt.Fprintln(a.out, a.paint(green, "The edge is up."))
		if bundle := a.currentBundle(cfg); bundle != nil && a.edgeBehind(cfg, bundle) {
			fmt.Fprintln(a.out, "It runs what was last installed there, which ctl has not matched to the files at home.")
			a.next(step{pushCommand, "send the edge the current configuration"}, step{cmdCheck, "verify the result"})
			return nil
		}
		a.next(step{cmdCheck, "verify the tunnel, certificates and firewall"})

	case "down":
		fmt.Fprintf(a.out, "This stops the edge stack on %s. Every published hostname goes offline and the\n", cfg.SSH)
		fmt.Fprintln(a.out, "tunnel closes until you start it again. Nothing is deleted: files, keys and containers stay.")
		if !o.yes {
			if ok, err := a.confirmOrYes("Stop the edge?"); err != nil {
				return err
			} else if !ok {
				return errCancelled
			}
		}
		if err := compose("Stopping the edge stack", "stop"); err != nil {
			return err
		}
		fmt.Fprintln(a.out, "The edge is stopped. It stays stopped, also after the VPS reboots, until you start it.")
		a.next(step{cmdEdgeUp, "bring the edge back"})

	case "restart":
		if err := compose("Restarting the edge stack", "restart"); err != nil {
			return err
		}
		fmt.Fprintln(a.out, a.paint(green, "The edge restarted.")+" Home reconnects on its own within about half a minute.")
		a.next(step{cmdCheck, "verify the tunnel, certificates and firewall"})

	case "logs":
		args := fmt.Sprintf("logs --no-color --tail %d", o.tail)
		if o.follow {
			args += " -f"
		}
		if o.service != "" {
			args += " " + o.service
		}
		err := c.ComposeStream(ctx, args, func(line string) { fmt.Fprintln(a.out, line) })
		if ctx.Err() != nil {
			return nil // Ctrl-C is how following ends
		}
		return err
	}
	return nil
}

// currentBundle is the edge bundle as generated at home, or nil when it
// cannot be rendered or does not match what is on disk.
func (a *app) currentBundle(cfg *config.Config) render.Files {
	files, ok := a.generated(cfg)
	if !ok {
		return nil
	}
	return files
}

// edgeState is what one query of the edge returns.
type edgeState struct {
	installed bool
	running   map[string]bool
	sums      map[string]string // file in the edge directory -> sha256
	handshake string            // output for handshakeAge
}

// edgeState asks the edge, in one connection, what is installed and running.
// Its output is parsed, never printed: the edge is not trusted.
func (a *app) edgeState(ctx context.Context, c *remote.Client, cfg *config.Config, paths []string) (*edgeState, error) {
	script := fmt.Sprintf(`cd %s 2>/dev/null || { echo ::absent; exit 0; }
test -f docker-compose.yml || { echo ::absent; exit 0; }
echo ::files
sha256sum %s 2>/dev/null
echo ::running
docker compose ps --services --status running || exit $?
echo ::tunnel
docker compose exec -T tunnel sh -c "wg show wg0 latest-handshakes; echo now; date +%%s" 2>/dev/null
exit 0`, cfg.EdgeDir, strings.Join(append([]string{"/dev/null"}, paths...), " "))
	out, err := c.Run(ctx, script, nil)
	if err != nil {
		return nil, err
	}
	return parseEdgeState(string(out)), nil
}

func parseEdgeState(out string) *edgeState {
	st := &edgeState{installed: true, running: map[string]bool{}, sums: map[string]string{}}
	section := ""
	var tunnel []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		switch line {
		case "::absent":
			st.installed = false
			return st
		case "::files", "::running", "::tunnel":
			section = line
			continue
		}
		switch section {
		case "::files":
			if f := strings.Fields(line); len(f) == 2 {
				st.sums[strings.TrimPrefix(f[1], "*")] = f[0]
			}
		case "::running":
			if s := strings.TrimSpace(line); s != "" {
				st.running[s] = true
			}
		case "::tunnel":
			tunnel = append(tunnel, line)
		}
	}
	st.handshake = strings.Join(tunnel, "\n")
	return st
}

// reportEdge prints the state of the edge: installed, running, up to date
// and connected to home. bundle may be nil, which skips the comparison.
// It returns the state, or nil if the edge could not be asked.
func (a *app) reportEdge(ctx context.Context, r *reporter, cfg *config.Config, bundle render.Files) *edgeState {
	r.section(fmt.Sprintf("Edge (%s)", cfg.SSH))
	c := a.client(cfg)
	defer c.Close()
	st, err := a.edgeState(ctx, c, cfg, bundle.Paths())
	if err != nil {
		r.fail("could not ask the edge")
		r.detail(err)
		return nil
	}
	if !st.installed {
		r.fail("the edge is not installed: there is no bundle in %s on the VPS", cfg.EdgeDir)
		r.hint("install and start it: " + pushCommand)
		return st
	}

	stopped := false
	for _, s := range edgeServices {
		if st.running[s] {
			r.ok("%s container is running", s)
		} else {
			r.fail("%s container is not running", s)
			stopped = true
		}
	}
	if stopped {
		r.hint("start the edge: "+cmdEdgeUp, "if it stops again, see why: docker compose run --rm ctl edge logs")
	}

	switch differ := differing(bundle, st.sums); {
	case bundle == nil:
		r.skip("cannot compare the edge with home until the generated files match hearthgate.yml")
	case len(differ) > 0:
		r.fail("the edge is out of date: %s there from generated/edge (%s)", plural(len(differ), "file differs"), strings.Join(differ, ", "))
		r.hint("send it the current configuration: " + pushCommand)
	default:
		r.ok("the edge has the configuration generated at home")
		a.markPushed(bundle)
	}

	switch age, err := handshakeAge(st.handshake); {
	case !st.running["tunnel"]:
		r.skip("tunnel: not checked while the tunnel container is stopped")
	case err != nil:
		r.fail("tunnel: %v", err)
		tunnelHints(r, cfg)
	case age > maxHandshakeAge:
		r.fail("tunnel: last handshake was %s ago; home is not connected", age.Round(time.Second))
		tunnelHints(r, cfg)
	default:
		r.ok("tunnel: home is connected, last handshake %s ago", age.Round(time.Second))
	}
	return st
}

// differing lists the bundle files whose checksum on the edge is missing or
// different.
func differing(bundle render.Files, sums map[string]string) []string {
	var out []string
	for _, p := range bundle.Paths() {
		sum := sha256.Sum256(bundle[p].Content)
		if sums[p] != hex.EncodeToString(sum[:]) {
			out = append(out, p)
		}
	}
	return out
}

// cmdStatus is the short answer to "is it working": the configuration at
// home and the state of the edge, without the certificate and firewall
// probes of `check`.
func (a *app) cmdStatus(ctx context.Context) error {
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	r := &reporter{app: a}
	files := a.reportConfig(r, cfg)
	if cfg.SSH == "" {
		r.section("Edge")
		r.skip("edge.ssh is not set, so the edge cannot be inspected")
	} else {
		var bundle render.Files
		if files != nil {
			bundle = files.WithPrefix(render.EdgeDir)
		}
		a.reportEdge(ctx, r, cfg, bundle)
	}
	if err := a.verdict(r); err != nil {
		return err
	}
	a.next(step{cmdCheck, "also test the certificates and probe the home firewall"})
	return nil
}

// verdict ends a report.
func (a *app) verdict(r *reporter) error {
	if r.failed > 0 {
		fmt.Fprintf(a.out, "\n%s\n", a.paint(red, plural(r.failed, "problem")+" found.")+" Fix the first one and look again: later ones often follow from it.")
		return errReported
	}
	fmt.Fprintf(a.out, "\n%s%s\n", a.paint(green, "Everything is in order."), warnings(r))
	return nil
}

func warnings(r *reporter) string {
	if r.warned == 0 {
		return ""
	}
	return " " + plural(r.warned, "warning") + " above."
}
