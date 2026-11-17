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
  init     Write a starting hearthgate.yml if there is none; once it is
           edited, generate keys and render both stacks
  apply    Re-render after editing hearthgate.yml, preview the diff, update the edge
  push     Copy the edge bundle to the VPS over SSH and start it
  bundle   Write the edge bundle to standard output, to install it with your own ssh
  check    Verify the tunnel, certificates and firewall
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
}

func run(ctx context.Context, args []string, in io.Reader, out, errw io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(out, usage)
		return 0
	}
	a := &app{in: bufio.NewReader(in), out: out, errw: errw}
	name, rest := args[0], args[1:]

	fs := flag.NewFlagSet("ctl "+name, flag.ContinueOnError)
	fs.SetOutput(errw)
	fs.StringVar(&a.dir, "dir", ".", "project directory")
	fs.StringVar(&a.cfgPath, "config", "", "config file (default <dir>/hearthgate.yml)")
	yes := false
	noPush := false

	var cmd func(context.Context) error
	switch name {
	case "init":
		cmd = a.cmdInit
	case "apply":
		fs.BoolVar(&yes, "yes", false, "apply without asking")
		fs.BoolVar(&noPush, "no-push", false, "do not update the edge over SSH")
		cmd = func(ctx context.Context) error { return a.cmdApply(ctx, yes, noPush) }
	case "push":
		cmd = a.cmdPush
	case "bundle":
		cmd = a.cmdBundle
	case "check":
		cmd = a.cmdCheck
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
	if fs.NArg() > 0 {
		fmt.Fprintf(errw, "unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if a.cfgPath == "" {
		a.cfgPath = filepath.Join(a.dir, "hearthgate.yml")
	}

	if err := cmd(ctx); err != nil {
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

// renderAll renders every file and adds the settings that depend on where ctl
// is running: the gateway runs as the project directory's owner, so generated
// files stay owned by that user.
func (a *app) renderAll(cfg *config.Config, st *state.State) (render.Files, error) {
	files, err := render.Render(cfg, st)
	if err != nil {
		return nil, err
	}
	if uid, gid, ok := dirOwner(a.dir); ok && uid != 0 {
		env := files[render.EnvFile]
		env.Content = append(env.Content, fmt.Appendf(nil, "HEARTHGATE_PUID=%d\nHEARTHGATE_PGID=%d\n", uid, gid)...)
		files[render.EnvFile] = env
	}
	return files, nil
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
		full := filepath.Join(a.dir, filepath.FromSlash(p))
		if info, err := os.Stat(full); err == nil && info.IsDir() {
			return nil, fmt.Errorf("%s is a directory, but it should be a file. Run `ctl apply` to repair it", p)
		}
		old, err := os.ReadFile(full)
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

func (a *app) printChanges(changes []change) {
	for _, c := range changes {
		fmt.Fprintf(a.out, "\n%s\n", c.path)
		for _, l := range c.lines {
			fmt.Fprintf(a.out, "  %s\n", l)
		}
	}
	fmt.Fprintln(a.out)
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

func (a *app) confirm(question string) (bool, error) {
	fmt.Fprintf(a.out, "%s [y/N] ", question)
	line, err := a.in.ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		fmt.Fprintln(a.out)
		return false, errNoAnswer
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
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
	fmt.Fprintf(a.out, "Pushing the edge bundle to %s:%s ...\n", cfg.SSH, cfg.EdgeDir)
	c := a.client(cfg)
	defer c.Close()
	out, err := c.Push(ctx, files.WithPrefix(render.EdgeDir))
	a.out.Write(out)
	if err != nil {
		return fmt.Errorf("the edge was not updated.\n\n%w\n\nTo install the edge with your own ssh setup instead (it may use ~/.ssh/config, jump hosts or a password):\n  %s", err, bundleCommand(cfg))
	}
	a.markPushed(files)
	fmt.Fprintln(a.out, "Edge updated.")
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

func (a *app) manualEdgeHint(cfg *config.Config) {
	fmt.Fprintf(a.out, "The edge bundle changed. Install it on the VPS:\n  %s\n", bundleCommand(cfg))
}

// scaffold is the first run in a new project directory: it writes a config
// for the user to edit, and generates nothing until they have.
func (a *app) scaffold() error {
	if err := os.WriteFile(a.cfgPath, render.ExampleConfig, 0o644); err != nil {
		return err
	}
	if uid, gid, ok := dirOwner(a.dir); ok && uid != 0 && os.Geteuid() == 0 {
		os.Chown(a.cfgPath, uid, gid)
	}
	name := filepath.Base(a.cfgPath)
	fmt.Fprintf(a.out, "Wrote a starting %s.\n\nNext:\n", name)
	fmt.Fprintf(a.out, "  edit %s\n", name)
	fmt.Fprintln(a.out, "  docker compose run --rm ctl init    # generate keys, render both stacks")
	return nil
}

func (a *app) cmdInit(ctx context.Context) error {
	if _, err := os.Stat(a.cfgPath); errors.Is(err, fs.ErrNotExist) {
		return a.scaffold()
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	if state.Exists(a.statePath()) {
		return fmt.Errorf("already initialised (%s exists).\nUse `ctl apply` after changing hearthgate.yml, or `ctl rotate` to replace the keys", a.statePath())
	}
	st, err := state.New()
	if err != nil {
		return err
	}
	files, err := a.renderAll(cfg, st)
	if err != nil {
		return err
	}
	if err := a.clearStrayDirs(files, false); err != nil {
		return err
	}
	if err := st.Save(a.statePath()); err != nil {
		return err
	}
	if err := a.write(files); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Generated keys and %d files under generated/.\n\nNext:\n", len(files))
	if cfg.SSH != "" {
		fmt.Fprintln(a.out, "  docker compose run --rm ctl push    # install and start the edge")
	} else {
		fmt.Fprintf(a.out, "  install and start the edge with your own ssh:\n    %s\n", bundleCommand(cfg))
	}
	fmt.Fprintln(a.out, "  docker compose up -d                # start the home gateway")
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
			return errors.New("aborted")
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
	if err := a.clearStrayDirs(files, yes); err != nil {
		return err
	}
	changes, err := a.pending(files)
	if err != nil {
		return err
	}
	if len(changes) == 0 {
		fmt.Fprintln(a.out, "Nothing to change: generated files already match hearthgate.yml.")
		if a.edgeBehind(cfg, files) && !noPush {
			fmt.Fprintf(a.out, "ctl has not pushed this configuration to the edge, though. Unless you installed it there yourself, run:\n  %s\n", pushCommand)
		}
		return nil
	}
	a.printChanges(changes)
	for _, note := range networkNotes(changes) {
		fmt.Fprintf(a.out, "%s\n\n", note)
	}
	if !yes {
		if ok, err := a.confirmOrYes("Apply these changes?"); err != nil {
			return fmt.Errorf("%w; nothing was written", err)
		} else if !ok {
			return errors.New("aborted; nothing was written")
		}
	}
	if saveState {
		if err := st.Save(a.statePath()); err != nil {
			return err
		}
	}
	if err := a.write(files); err != nil {
		return err
	}
	fmt.Fprintln(a.out, "Generated files updated.")

	if touches(changes, render.EdgeDir) {
		switch {
		case cfg.SSH != "" && !noPush:
			if err := a.push(ctx, cfg, files); err != nil {
				return fmt.Errorf("%w\n\n%s", err, afterFailedPush(saveState))
			}
		default:
			a.manualEdgeHint(cfg)
		}
	}
	if touches(changes, render.HomeDir) || touches(changes, render.EnvFile) {
		fmt.Fprintln(a.out, "Now run `docker compose up -d` to update the home gateway.")
	}
	return nil
}

func (a *app) cmdPush(ctx context.Context) error {
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	if cfg.SSH == "" {
		a.manualEdgeHint(cfg)
		return errors.New("edge.ssh is not set, so there is nowhere to push to")
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
	return a.push(ctx, cfg, files)
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
