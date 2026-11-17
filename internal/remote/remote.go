// Package remote talks to the edge server through the system ssh client.
package remote

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/xrvo/hearthgate/internal/render"
)

// Client runs commands on the edge server.
type Client struct {
	Target     string // user@host, already validated by the config package
	Port       int
	Dir        string    // remote directory, already validated
	KnownHosts string    // known_hosts file kept with the generated state
	KeyDir     string    // directory holding the user's SSH keys, may not exist
	KeyDirName string    // what to call KeyDir in messages; in the container, the host's path
	AgentSock  string    // SSH agent socket, may be empty or not a socket
	Owner      int       // uid that owns the project directory, 0 if unknown
	Stderr     io.Writer // receives ssh's own output and notices about the connection

	tmp    string
	auth   *authState
	loaded bool
}

// Close removes temporary key copies.
func (c *Client) Close() {
	if c.tmp != "" {
		os.RemoveAll(c.tmp)
	}
}

func (c *Client) args() ([]string, error) {
	args := []string{
		"-F", "/dev/null",
		"-p", strconv.Itoa(c.Port),
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile=" + c.KnownHosts,
		"-o", "ConnectTimeout=15",
	}
	auth, err := c.identities()
	if err != nil {
		return nil, err
	}
	for _, k := range auth.keys {
		args = append(args, "-i", k.path)
	}
	return append(args, c.Target), nil
}

// Run executes a shell script on the edge and returns its standard output.
// When it fails, the error says what went wrong and what to try.
func (c *Client) Run(ctx context.Context, script string, stdin io.Reader) ([]byte, error) {
	return c.run(ctx, script, stdin, nil)
}

// run is Run, also handing each line of standard output to live as it arrives.
func (c *Client) run(ctx context.Context, script string, stdin io.Reader, live func(string)) ([]byte, error) {
	if _, err := exec.LookPath("ssh"); err != nil {
		return nil, errors.New("no ssh client found; run ctl from its container image, or install the edge bundle by hand")
	}
	args, err := c.args()
	if err != nil {
		return nil, err
	}
	known, _ := os.ReadFile(c.KnownHosts)
	// A new host key is announced as soon as the edge says anything, so the
	// fingerprint comes before the edge's output and not after it.
	announced := false
	announce := func() {
		if !announced {
			announced = true
			c.announceHostKeys(known)
		}
	}

	cmd := exec.CommandContext(ctx, "ssh", append(args, script)...)
	cmd.Env = c.env()
	cmd.Stdin = stdin
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	var stream *lineWriter
	if live != nil {
		stream = &lineWriter{fn: func(line string) {
			announce()
			live(line)
		}}
		cmd.Stdout = io.MultiWriter(&out, stream)
	}
	// ssh's standard error also carries what the edge's command wrote to its own.
	shown := &lineWriter{fn: func(line string) {
		if c.Stderr != nil && !strings.HasPrefix(line, "Warning: Permanently added") {
			fmt.Fprintln(c.Stderr, line)
		}
	}}
	cmd.Stderr = io.MultiWriter(shown, &errBuf)
	runErr := cmd.Run()
	shown.Flush()
	if stream != nil {
		stream.Flush()
	}
	announce()

	if runErr == nil {
		return out.Bytes(), nil
	}
	if ctx.Err() != nil {
		return out.Bytes(), ctx.Err()
	}
	code := -1
	var exit *exec.ExitError
	if errors.As(runErr, &exit) {
		code = exit.ExitCode()
	}
	output := errBuf.String() + out.String()
	if msg := c.explain(classify(code, output), output); msg != "" {
		return out.Bytes(), errors.New(msg)
	}
	return out.Bytes(), fmt.Errorf("ssh %s: %w", c.Target, runErr)
}

// env is the environment for ssh. A missing agent is mounted as /dev/null in
// the container; pointing ssh at that only adds noise to its errors.
func (c *Client) env() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "SSH_AUTH_SOCK=") {
			env = append(env, kv)
		}
	}
	if isSocket(c.AgentSock) {
		env = append(env, "SSH_AUTH_SOCK="+c.AgentSock)
	}
	return env
}

// announceHostKeys reports host keys that this run added to KnownHosts.
// They are accepted on first use, so the user should at least see them.
func (c *Client) announceHostKeys(before []byte) {
	after, err := os.ReadFile(c.KnownHosts)
	if err != nil || bytes.Equal(before, after) {
		return
	}
	old := map[string]bool{}
	for _, l := range strings.Split(string(before), "\n") {
		old[l] = true
	}
	for _, l := range strings.Split(string(after), "\n") {
		if old[l] {
			continue
		}
		if kind, fp, ok := fingerprint(l); ok {
			fmt.Fprintf(c.Stderr, "First connection to %s: saved its %s host key in %s.\n  Fingerprint: %s\n  To verify, compare with `ssh-keygen -lf /etc/ssh/ssh_host_%s_key.pub` run on the VPS.\n",
				c.host(), strings.ToUpper(kind), c.KnownHosts, fp, kind)
		}
	}
}

func (c *Client) host() string {
	_, host, _ := strings.Cut(c.Target, "@")
	return host
}

func (c *Client) user() string {
	user, _, _ := strings.Cut(c.Target, "@")
	return user
}

// MarkCopied is the line the push script prints once the bundle is unpacked
// on the edge, before it starts the stack.
const MarkCopied = "hearthgate:copied"

// Push installs the edge bundle and starts or updates the edge stack. Each
// line the edge prints is handed to onLine as it arrives.
func (c *Client) Push(ctx context.Context, bundle render.Files, onLine func(string)) error {
	archive, err := Archive(bundle, time.Now())
	if err != nil {
		return err
	}
	script := "set -eu\n" + unpackScript(c.Dir) + "\necho " + MarkCopied + "\n" + startScript + " 2>&1"
	_, err = c.run(ctx, script, bytes.NewReader(archive), onLine)
	return err
}

func unpackScript(dir string) string {
	return fmt.Sprintf("mkdir -p %[1]s && cd %[1]s && tar -xzf -", dir)
}

const startScript = "docker compose up -d --remove-orphans"

// InstallScript is the shell command that installs a bundle archive read from
// standard input into dir and starts the edge stack. dir must be validated.
// It contains no single quotes, so it can be passed to ssh inside a pair.
func InstallScript(dir string) string {
	return unpackScript(dir) + " && " + startScript
}

// Compose runs `docker compose <args>` in the edge directory. Arguments must
// be trusted: they are passed to the remote shell as written.
func (c *Client) Compose(ctx context.Context, args string) ([]byte, error) {
	return c.Run(ctx, fmt.Sprintf("cd %s && docker compose %s", c.Dir, args), nil)
}

// ComposeStream is Compose for commands whose output is the point: each line,
// from either stream, is handed to onLine as it arrives.
func (c *Client) ComposeStream(ctx context.Context, args string, onLine func(string)) error {
	_, err := c.run(ctx, fmt.Sprintf("cd %s && docker compose %s 2>&1", c.Dir, args), nil, onLine)
	return err
}

// Archive packs the bundle as a gzipped tarball.
func Archive(bundle render.Files, modTime time.Time) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, p := range bundle.Paths() {
		f := bundle[p]
		hdr := &tar.Header{
			Name:    p,
			Mode:    int64(f.Mode.Perm()),
			Size:    int64(len(f.Content)),
			ModTime: modTime,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.Content); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
