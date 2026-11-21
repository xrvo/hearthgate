// Command ctl generates and deploys Hearthgate's configuration.
//
// It runs one-shot on the home server, normally through
// `docker compose run --rm ctl <command>`, and never listens on the network.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/xrvo/hearthgate/internal/config"
	"github.com/xrvo/hearthgate/internal/diff"
	"github.com/xrvo/hearthgate/internal/remote"
	"github.com/xrvo/hearthgate/internal/render"
	"github.com/xrvo/hearthgate/internal/state"
)

var version = "dev"

const usage = `Hearthgate ctl: generate and deploy the tunnel configuration.

Usage: ctl <command> [flags]

Commands:
  init     Set up a new project: ask for the VPS and a first hostname, write
           hearthgate.yml, generate keys and render both stacks
  deploy   Bring the edge in line with hearthgate.yml: check the VPS, apply
           changes, push, wait for the tunnel and verify
  apply    Re-render after editing hearthgate.yml, preview the diff, update the edge
  push     Copy the edge bundle to the VPS over SSH and start it
  bundle   Write the edge bundle to standard output, to install it with your own ssh
  status   Show whether both sides are in step and the tunnel is connected
  check    Verify the tunnel, certificates and firewall
  edge     Start, stop or inspect the edge: edge <up|down|restart|status|logs>
  rotate   Replace the WireGuard keys on both sides
  version  Print the version

Common flags:
  -dir string      project directory (default ".")
  -config string   config file (default "<dir>/hearthgate.yml")

Run "ctl <command> -h" for the flags of one command.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

type app struct {
	dir     string
	cfgPath string
	in      *bufio.Reader
	out     io.Writer
	errw    io.Writer
	color   bool
	ctx     context.Context // cancelled by Ctrl-C
}

func run(ctx context.Context, args []string, in io.Reader, out, errw io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(out, usage)
		return 0
	}
	a := &app{in: bufio.NewReader(in), out: out, errw: errw, color: useColor(out), ctx: ctx}
	name, rest := args[0], args[1:]

	fs := flag.NewFlagSet("ctl "+name, flag.ContinueOnError)
	fs.SetOutput(errw)
	fs.StringVar(&a.dir, "dir", ".", "project directory")
	fs.StringVar(&a.cfgPath, "config", "", "config file (default <dir>/hearthgate.yml)")
	yes := false
	noPush := false
	wait := 60
	var edge edgeOpts

	var cmd func(context.Context) error
	switch name {
	case "init":
		cmd = a.cmdInit
	case "apply":
		fs.BoolVar(&yes, "yes", false, "apply without asking")
		fs.BoolVar(&noPush, "no-push", false, "do not update the edge over SSH")
		cmd = func(ctx context.Context) error { return a.cmdApply(ctx, yes, noPush) }
	case "deploy":
		fs.BoolVar(&yes, "yes", false, "apply pending changes without asking")
		fs.IntVar(&wait, "wait", 60, "seconds to wait for home to connect")
		cmd = func(ctx context.Context) error { return a.cmdDeploy(ctx, yes, time.Duration(wait)*time.Second) }
	case "push":
		cmd = a.cmdPush
	case "bundle":
		cmd = a.cmdBundle
	case "check":
		cmd = a.cmdCheck
	case "status":
		cmd = a.cmdStatus
	case "edge":
		fs.Usage = func() { fmt.Fprint(errw, edgeUsage) }
		fs.BoolVar(&edge.yes, "yes", false, "stop the edge without asking")
		fs.BoolVar(&edge.follow, "f", false, "keep showing new log lines")
		fs.IntVar(&edge.tail, "tail", 50, "how many log lines to show")
		cmd = func(ctx context.Context) error { return a.cmdEdge(ctx, edge) }
	case "rotate":
		fs.BoolVar(&yes, "yes", false, "rotate without asking")
		fs.BoolVar(&noPush, "no-push", false, "do not update the edge over SSH")
		cmd = func(ctx context.Context) error { return a.cmdRotate(ctx, yes, noPush) }
	case "version":
		fmt.Fprintln(out, version)
		return 0
	default:
		fmt.Fprintf(errw, "unknown command %q\n\n%s", name, usage)
		return 2
	}
	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if name == "edge" {
		// The subcommand comes first, then its flags, then for logs a service.
		edge.sub = fs.Arg(0)
		if fs.NArg() > 0 {
			if err := fs.Parse(fs.Args()[1:]); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return 0
				}
				return 2
			}
		}
		edge.service = fs.Arg(0)
		if err := edge.validate(); err != nil || fs.NArg() > 1 {
			if err == nil {
				err = fmt.Errorf("unexpected argument %q", fs.Arg(1))
			}
			fmt.Fprintf(errw, "%v\n\n%s", err, edgeUsage)
			return 2
		}
	} else if fs.NArg() > 0 {
		fmt.Fprintf(errw, "unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if a.cfgPath == "" {
		a.cfgPath = filepath.Join(a.dir, "hearthgate.yml")
	}

	if err := cmd(ctx); err != nil {
		if errors.Is(err, errCancelled) {
			fmt.Fprintln(out, "Cancelled; nothing was written.")
			return 1
		}
		if !errors.Is(err, errReported) {
			fmt.Fprintf(errw, "error: %v\n", withPermissionHelp(err))
		}
		return 1
	}
	return 0
}

// errReported marks a failure whose details were already printed.
var errReported = errors.New("failed")

func (a *app) statePath() string { return filepath.Join(a.dir, "generated", "state.json") }

func (a *app) loadConfig() (*config.Config, error) {
	data, err := os.ReadFile(a.cfgPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s not found: run `ctl init` to create one, then edit it", a.cfgPath)
	}
	if err != nil {
		return nil, err
	}
	cfg, err := config.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s:\n%w", a.cfgPath, err)
	}
	if lines := placeholders(data); len(lines) > 0 {
		return nil, fmt.Errorf("%s still has values from the example:\n  %s\nReplace them with your VPS's address and your own hostname, then run this command again",
			a.cfgPath, strings.Join(lines, "\n  "))
	}
	return cfg, nil
}

var reImage = regexp.MustCompile(`^[a-z0-9][a-zA-Z0-9._/:@-]{0,254}$`)

// edgeImages are the images the edge stack runs. The home stack's compose
// file passes its own in HEARTHGATE_WIREGUARD_IMAGE and HEARTHGATE_NGINX_IMAGE,
// so both sides always run the same versions and docker-compose.yml is the
// one place they are set.
func edgeImages() (render.Images, error) {
	wireguard, err := imageFromEnv("HEARTHGATE_WIREGUARD_IMAGE", "WireGuard")
	if err != nil {
		return render.Images{}, err
	}
	nginx, err := imageFromEnv("HEARTHGATE_NGINX_IMAGE", "nginx")
	if err != nil {
		return render.Images{}, err
	}
	return render.Images{WireGuard: wireguard, Nginx: nginx}, nil
}

func imageFromEnv(name, what string) (string, error) {
	image := os.Getenv(name)
	if image == "" {
		return "", fmt.Errorf("%s is not set, so ctl cannot tell which %s the edge should run.\n"+
			"Run ctl through the compose file, which sets it: docker compose run --rm ctl <command>", name, what)
	}
	if !reImage.MatchString(image) {
		return "", fmt.Errorf("%s %q is not a valid image reference", name, image)
	}
	return image, nil
}

func (a *app) renderAll(cfg *config.Config, st *state.State) (render.Files, error) {
	images, err := edgeImages()
	if err != nil {
		return nil, err
	}
	var owner *render.Owner
	if uid, gid, ok := fileOwner(a.dir); ok {
		owner = &render.Owner{UID: uid, GID: gid}
	}
	return render.Render(cfg, st, images, owner)
}

type change struct {
	path  string
	lines []string
}

// pending compares rendered files with what is on disk. Secrets are redacted
// before comparing, so the result is safe to print.
func (a *app) pending(files render.Files) ([]change, error) {
	var out []change
	for _, p := range files.Paths() {
		old, err := os.ReadFile(filepath.Join(a.dir, filepath.FromSlash(p)))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if bytes.Equal(old, files[p].Content) {
			continue
		}
		lines := diff.Lines(diff.Redact(string(old)), diff.Redact(string(files[p].Content)))
		out = append(out, change{path: p, lines: lines})
	}
	return out, nil
}

func touches(changes []change, prefix string) bool {
	for _, c := range changes {
		if strings.HasPrefix(c.path, prefix) {
			return true
		}
	}
	return false
}

// write stores changed files only, in place, so the bind mounts of running
// containers keep pointing at the same files.
func (a *app) write(files render.Files) error {
	uid, gid, owned := dirOwner(a.dir)
	for _, p := range files.Paths() {
		f := files[p]
		full := filepath.Join(a.dir, filepath.FromSlash(p))
		if old, err := os.ReadFile(full); err == nil && bytes.Equal(old, f.Content) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, f.Content, f.Mode); err != nil {
			return err
		}
		if err := os.Chmod(full, f.Mode); err != nil {
			return err
		}
	}
	if owned && uid != 0 && os.Geteuid() == 0 {
		chownTree(filepath.Join(a.dir, "generated"), uid, gid)
		os.Chown(filepath.Join(a.dir, render.EnvFile), uid, gid)
	}
	return nil
}

// errNoAnswer means a question could not be asked: standard input is closed,
// as it is under cron, in a pipe, or with `docker compose run -T`.
var errNoAnswer = errors.New("this needs a yes or no, and there is no terminal to ask on")

// ask prints a prompt and returns the trimmed answer. Ctrl-C while it waits
// cancels the command instead of being ignored until Enter.
func (a *app) ask(prompt string) (string, error) {
	fmt.Fprint(a.out, prompt)
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := a.in.ReadString('\n')
		ch <- result{line, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil && strings.TrimSpace(r.line) == "" {
			fmt.Fprintln(a.out)
			return "", errNoAnswer
		}
		return strings.TrimSpace(r.line), nil
	case <-a.ctx.Done():
		fmt.Fprintln(a.out)
		return "", errCancelled
	}
}

func (a *app) confirm(question string) (bool, error) {
	line, err := a.ask(question + " [y/N] ")
	if err != nil {
		return false, err
	}
	switch strings.ToLower(line) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// confirmOrYes asks a question that the -yes flag would have answered.
func (a *app) confirmOrYes(question string) (bool, error) {
	ok, err := a.confirm(question)
	if errors.Is(err, errNoAnswer) {
		return false, fmt.Errorf("%w.\nTo go ahead without being asked, add -yes to the command", err)
	}
	return ok, err
}

func (a *app) client(cfg *config.Config) *remote.Client {
	// In the container the keys are mounted at /ssh, and compose passes the
	// folder's real path so messages can name it.
	keyDir := os.Getenv("HEARTHGATE_SSH_DIR")
	if keyDir == "" {
		keyDir = "/ssh"
	}
	owner, _, _ := dirOwner(a.dir)
	return &remote.Client{
		Target:     cfg.SSH,
		Port:       cfg.SSHPort,
		Dir:        cfg.EdgeDir,
		KnownHosts: filepath.Join(a.dir, "generated", "known_hosts"),
		KeyDir:     keyDir,
		KeyDirName: os.Getenv("HEARTHGATE_SSH_DIR_HOST"),
		AgentSock:  os.Getenv("SSH_AUTH_SOCK"),
		Owner:      owner,
		Stderr:     a.errw,
	}
}

func (a *app) push(ctx context.Context, cfg *config.Config, files render.Files) error {
	bundle := files.WithPrefix(render.EdgeDir)
	fmt.Fprintf(a.out, "Connecting to %s (port %d) ...\n", cfg.SSH, cfg.SSHPort)
	c := a.client(cfg)
	defer c.Close()
	err := c.Push(ctx, bundle, func(line string) {
		if line == remote.MarkCopied {
			fmt.Fprintf(a.out, "Copied %s to %s:%s. Starting the edge stack ...\n", plural(len(bundle), "file"), cfg.SSH, cfg.EdgeDir)
			return
		}
		fmt.Fprintf(a.out, "  %s %s\n", a.paint(dim, "edge |"), line)
	})
	if err != nil {
		return fmt.Errorf("the edge was not updated.\n\n%w\n\nTo install the edge with your own ssh setup instead (it may use ~/.ssh/config, jump hosts or a password):\n  %s", err, bundleCommand(cfg))
	}
	a.markPushed(files)
	fmt.Fprintln(a.out, a.paint(green, "The edge is running this configuration."))
	return nil
}

// bundleCommand is the one-line manual install: it pipes the bundle through
// the user's own ssh client on the home server.
func bundleCommand(cfg *config.Config) string {
	target := cfg.SSH
	if target == "" {
		target = "<user>@" + cfg.EdgeAddress
	}
	if cfg.SSHPort != config.DefaultSSHPort {
		target = fmt.Sprintf("-p %d %s", cfg.SSHPort, target)
	}
	return fmt.Sprintf("docker compose run --rm -T ctl bundle | ssh %s '%s'", target, remote.InstallScript(cfg.EdgeDir))
}

// manualStep is the edge install for setups ctl does not push to.
func manualStep(cfg *config.Config) step {
	return step{bundleCommand(cfg), "install the edge bundle on the VPS and start it, with your own ssh"}
}

// scaffold is the first run in a new project directory: it writes a config
// for the user to edit, and generates nothing until they have.
func (a *app) scaffold() error {
	if err := a.writeConfig(render.ExampleConfig); err != nil {
		return err
	}
	name := filepath.Base(a.cfgPath)
	fmt.Fprintf(a.out, "Wrote a starting %s. Nothing else was generated yet.\n", name)
	a.next(
		step{"edit " + name, "set your VPS address and the hostnames to publish"},
		step{"docker compose run --rm ctl init", "generate keys and both stacks' files"},
	)
	return nil
}

func (a *app) cmdInit(ctx context.Context) error {
	if _, err := os.Stat(a.cfgPath); errors.Is(err, fs.ErrNotExist) {
		w, err := a.interview()
		if errors.Is(err, errNoAnswer) {
			fmt.Fprintln(a.out, "There is no terminal to ask on, so here is an example to edit instead.")
			return a.scaffold()
		}
		if err != nil {
			return err
		}
		if err := a.writeConfig(w.document()); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "\nWrote %s. Edit it any time to publish more hostnames or change settings.\n", filepath.Base(a.cfgPath))
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	if state.Exists(a.statePath()) {
		return a.initStatus(cfg)
	}
	st, err := state.New()
	if err != nil {
		return err
	}
	files, err := a.renderAll(cfg, st)
	if err != nil {
		return err
	}
	if err := st.Save(a.statePath()); err != nil {
		return err
	}
	if err := a.write(files); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Generated the tunnel keys and %s:\n", plural(len(files), "file"))
	fmt.Fprintf(a.out, "  generated/state.json  the keys; keep this file private and backed up\n")
	fmt.Fprintf(a.out, "  generated/home/       what the home gateway runs from\n")
	fmt.Fprintf(a.out, "  generated/edge/       the bundle for the VPS\n")
	fmt.Fprintf(a.out, "  .env                  settings `docker compose` reads for the home stack\n")
	if cfg.SSH == "" {
		a.next(manualStep(cfg), step{cmdUp, "start the home gateway"}, step{cmdCheck, "verify the certificates"})
		return nil
	}
	a.next(step{cmdUp, "start the home gateway; it keeps trying until the edge is there"},
		step{cmdDeploy, "install the edge on " + cfg.SSH + ", wait for the tunnel and verify"})
	return nil
}

// initStatus is `init` on a project that is already set up. It changes
// nothing and says what the user probably wanted instead.
func (a *app) initStatus(cfg *config.Config) error {
	st, err := state.Load(a.statePath())
	if err != nil {
		return err
	}
	files, err := a.renderAll(cfg, st)
	if err != nil {
		return err
	}
	changes, err := a.pending(files)
	if err != nil {
		return err
	}
	fmt.Fprintln(a.out, "Already set up: the keys and generated files are in place, so init changed nothing.")
	switch {
	case len(changes) > 0:
		fmt.Fprintf(a.out, "hearthgate.yml has changed since they were generated (%s).\n", plural(len(changes), "file differs"))
		a.next(step{cmdApply, "preview and apply the change"})
	case a.edgeBehind(cfg, files):
		fmt.Fprintln(a.out, "ctl has not pushed this configuration to the edge yet.")
		a.next(step{cmdUp, "start the home gateway, if it is not running"}, step{cmdDeploy, "install the edge on " + cfg.SSH + ", wait for the tunnel and verify"})
	default:
		a.next(step{cmdUp, "start the home gateway, if it is not running"}, step{cmdCheck, "verify the tunnel, certificates and firewall"})
	}
	fmt.Fprintln(a.out, "\nTo change the configuration, edit hearthgate.yml and run `ctl apply`. To replace the keys, run `ctl rotate`.")
	return nil
}

func (a *app) cmdApply(ctx context.Context, yes, noPush bool) error {
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	st, err := state.Load(a.statePath())
	if err != nil {
		return err
	}
	return a.applyState(ctx, cfg, st, yes, noPush, false)
}

func (a *app) cmdRotate(ctx context.Context, yes, noPush bool) error {
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	if _, err := state.Load(a.statePath()); err != nil {
		return err
	}
	fmt.Fprintln(a.out, "This replaces the WireGuard keys on both sides. The tunnel is down from the")
	fmt.Fprintln(a.out, "moment the edge restarts until you run `docker compose up -d` at home.")
	if !yes {
		if ok, err := a.confirmOrYes("Rotate keys?"); err != nil {
			return err
		} else if !ok {
			return errCancelled
		}
	}
	st, err := state.New()
	if err != nil {
		return err
	}
	return a.applyState(ctx, cfg, st, true, noPush, true)
}

func (a *app) applyState(ctx context.Context, cfg *config.Config, st *state.State, yes, noPush, saveState bool) error {
	files, err := a.renderAll(cfg, st)
	if err != nil {
		return err
	}
	changes, err := a.stage(cfg, st, files, yes, saveState)
	if err != nil {
		return err
	}
	if len(changes) == 0 {
		fmt.Fprintln(a.out, "Nothing to change: generated files already match hearthgate.yml.")
		if a.edgeBehind(cfg, files) && !noPush {
			fmt.Fprintln(a.out, "ctl has not pushed this configuration to the edge, though.")
			a.next(step{pushCommand, "unless you installed it on the VPS yourself"})
		}
		return nil
	}

	var steps []step
	if touches(changes, render.EdgeDir) {
		switch {
		case cfg.SSH != "" && !noPush:
			if err := a.push(ctx, cfg, files); err != nil {
				return fmt.Errorf("%w\n\n%s", err, afterFailedPush(saveState))
			}
		default:
			fmt.Fprintln(a.out, "The edge bundle changed, and the edge does not have it yet.")
			steps = append(steps, manualStep(cfg))
		}
	}
	if touches(changes, render.HomeDir) || touches(changes, render.EnvFile) {
		steps = append(steps, step{cmdUp, "restart the home gateway with the new files"})
	} else {
		fmt.Fprintln(a.out, "Nothing changed for the home gateway.")
	}
	a.next(append(steps, step{cmdCheck, "verify the result"})...)
	return nil
}

func (a *app) cmdPush(ctx context.Context) error {
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	if cfg.SSH == "" {
		return fmt.Errorf("edge.ssh is not set, so there is nowhere to push to.\nSet it in hearthgate.yml, or install the edge with your own ssh:\n  %s", bundleCommand(cfg))
	}
	st, err := state.Load(a.statePath())
	if err != nil {
		return err
	}
	files, err := a.renderAll(cfg, st)
	if err != nil {
		return err
	}
	changes, err := a.pending(files)
	if err != nil {
		return err
	}
	if len(changes) > 0 {
		return errors.New("generated files do not match hearthgate.yml; run `ctl apply` first")
	}
	if err := a.push(ctx, cfg, files); err != nil {
		return err
	}
	a.next(step{cmdUp, "start the home gateway, or restart it after a change"}, step{cmdCheck, "verify the tunnel, certificates and firewall"})
	return nil
}

// cmdBundle writes the edge bundle as a gzipped tarball to standard output.
// Everything else it has to say goes to standard error.
func (a *app) cmdBundle(ctx context.Context) error {
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	st, err := state.Load(a.statePath())
	if err != nil {
		return err
	}
	files, err := a.renderAll(cfg, st)
	if err != nil {
		return err
	}
	changes, err := a.pending(files)
	if err != nil {
		return err
	}
	if len(changes) > 0 {
		return errors.New("generated files do not match hearthgate.yml; run `ctl apply` first")
	}
	if isTerminal(a.out) {
		return fmt.Errorf("the bundle is a binary archive, and a terminal would corrupt it.\nPipe it to the VPS (note the -T):\n  %s", bundleCommand(cfg))
	}
	archive, err := remote.Archive(files.WithPrefix(render.EdgeDir), time.Now())
	if err != nil {
		return err
	}
	_, err = a.out.Write(archive)
	return err
}

// isTerminal reports whether w is a terminal. `docker compose run` gives the
// container one unless it is passed -T.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
