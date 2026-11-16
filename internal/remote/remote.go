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
	"path/filepath"
	"strconv"
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
	Stderr     io.Writer // receives ssh's own output (prompts, errors)

	tmp string
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
	keys, err := c.identities()
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		args = append(args, "-i", k)
	}
	return append(args, c.Target), nil
}

// identities copies the usual private keys out of KeyDir with strict
// permissions. A read-only mount of ~/.ssh can present modes or owners that
// ssh refuses to use directly.
func (c *Client) identities() ([]string, error) {
	if c.KeyDir == "" {
		return nil, nil
	}
	var out []string
	for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		data, err := os.ReadFile(filepath.Join(c.KeyDir, name))
		if err != nil {
			continue
		}
		if c.tmp == "" {
			if c.tmp, err = os.MkdirTemp("", "hearthgate-ssh-"); err != nil {
				return nil, err
			}
		}
		dst := filepath.Join(c.tmp, name)
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			return nil, err
		}
		out = append(out, dst)
	}
	return out, nil
}

// Run executes a shell script on the edge and returns its standard output.
func (c *Client) Run(ctx context.Context, script string, stdin io.Reader) ([]byte, error) {
	if _, err := exec.LookPath("ssh"); err != nil {
		return nil, errors.New("no ssh client found; run ctl from its container image, or install the edge bundle by hand")
	}
	args, err := c.args()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "ssh", append(args, script)...)
	cmd.Stdin = stdin
	cmd.Stderr = c.Stderr
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("ssh %s: %w", c.Target, err)
	}
	return out.Bytes(), nil
}

// Push installs the edge bundle and starts or updates the edge stack.
// The .env it writes makes the tunnel container run as the SSH user, so the
// bundle's files stay writable for the next push.
func (c *Client) Push(ctx context.Context, bundle render.Files) ([]byte, error) {
	archive, err := Archive(bundle, time.Now())
	if err != nil {
		return nil, err
	}
	script := fmt.Sprintf(`set -eu
mkdir -p '%[1]s'
cd '%[1]s'
tar -xzf -
printf 'HEARTHGATE_PUID=%%s\nHEARTHGATE_PGID=%%s\n' "$(id -u)" "$(id -g)" > .env
docker compose up -d --remove-orphans 2>&1`, c.Dir)
	return c.Run(ctx, script, bytes.NewReader(archive))
}

// Compose runs `docker compose <args>` in the edge directory. Arguments must
// be trusted: they are passed to the remote shell as written.
func (c *Client) Compose(ctx context.Context, args string) ([]byte, error) {
	return c.Run(ctx, fmt.Sprintf("cd '%s' && docker compose %s", c.Dir, args), nil)
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
