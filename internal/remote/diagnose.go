package remote

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// keyNames are the private keys ctl looks for in KeyDir, in the order ssh
// would try them.
var keyNames = []string{"id_ed25519", "id_ecdsa", "id_rsa"}

type identity struct {
	name      string
	path      string // private copy that ssh reads
	encrypted bool
}

// authState is what ctl found to sign in with. It is gathered once and used
// both to build the ssh command and to explain a refused sign-in.
type authState struct {
	keys       []identity
	unreadable []string // "id_rsa: permission denied"
	dirMissing bool
	dirEmpty   bool
	dirRoot    bool // KeyDir is owned by root
}

// identities copies the usual private keys out of KeyDir with strict
// permissions. A read-only mount of ~/.ssh can present modes or owners that
// ssh refuses to use directly.
func (c *Client) identities() (*authState, error) {
	if c.loaded {
		return c.auth, nil
	}
	a := &authState{}
	c.auth, c.loaded = a, true
	if c.KeyDir == "" {
		a.dirMissing = true
		return a, nil
	}
	entries, err := os.ReadDir(c.KeyDir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		a.dirMissing = true
		return a, nil
	case err != nil:
		a.unreadable = append(a.unreadable, reason(err))
		return a, nil
	}
	a.dirEmpty = len(entries) == 0
	if uid, ok := ownerOf(c.KeyDir); ok {
		a.dirRoot = uid == 0
	}
	for _, name := range keyNames {
		data, err := os.ReadFile(filepath.Join(c.KeyDir, name))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			a.unreadable = append(a.unreadable, name+": "+reason(err))
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
		a.keys = append(a.keys, identity{name: name, path: dst, encrypted: encrypted(data)})
	}
	return a, nil
}

func reason(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// encrypted reports whether a private key file is protected by a passphrase.
func encrypted(data []byte) bool {
	s := string(data)
	const begin = "-----BEGIN OPENSSH PRIVATE KEY-----"
	i := strings.Index(s, begin)
	if i < 0 {
		// PEM keys say so in a header or in the block type.
		return strings.Contains(s, "ENCRYPTED")
	}
	body := s[i+len(begin):]
	if j := strings.Index(body, "-----END"); j >= 0 {
		body = body[:j]
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(body), ""))
	const magic = "openssh-key-v1\x00"
	if err != nil || !bytes.HasPrefix(raw, []byte(magic)) {
		return false
	}
	// The cipher name follows as a length-prefixed string.
	raw = raw[len(magic):]
	if len(raw) < 4 {
		return false
	}
	n := int(binary.BigEndian.Uint32(raw))
	if n > len(raw)-4 {
		return false
	}
	return string(raw[4:4+n]) != "none"
}

func isSocket(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode()&fs.ModeSocket != 0
}

// agentKeys returns how many keys the SSH agent holds, or -1 if it cannot
// be asked.
func (c *Client) agentKeys() int {
	cmd := exec.Command("ssh-add", "-l")
	cmd.Env = c.env()
	out, err := cmd.Output()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return strings.Count(strings.TrimSpace(string(out)), "\n") + 1
	case errors.As(err, &exit) && exit.ExitCode() == 1:
		return 0 // "The agent has no identities."
	}
	return -1
}

// fingerprint returns the key type and SHA256 fingerprint of a known_hosts
// line, in the form ssh-keygen prints.
func fingerprint(line string) (kind, fp string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 || strings.HasPrefix(fields[0], "#") {
		return "", "", false
	}
	blob, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		return "", "", false
	}
	switch t := fields[1]; {
	case t == "ssh-ed25519":
		kind = "ed25519"
	case t == "ssh-rsa":
		kind = "rsa"
	case strings.HasPrefix(t, "ecdsa-"):
		kind = "ecdsa"
	default:
		kind = t
	}
	sum := sha256.Sum256(blob)
	return kind, "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), true
}

// lineFilter passes whole lines through to w, leaving out those that start
// with drop.
type lineFilter struct {
	w    io.Writer
	drop string
	buf  []byte
}

func (f *lineFilter) Write(p []byte) (int, error) {
	f.buf = append(f.buf, p...)
	for {
		i := bytes.IndexByte(f.buf, '\n')
		if i < 0 {
			return len(p), nil
		}
		f.emit(f.buf[:i+1])
		f.buf = f.buf[i+1:]
	}
}

// Flush writes out a last line that had no newline.
func (f *lineFilter) Flush() {
	if len(f.buf) > 0 {
		f.emit(f.buf)
		f.buf = nil
	}
}

func (f *lineFilter) emit(line []byte) {
	if f.w != nil && !bytes.HasPrefix(line, []byte(f.drop)) {
		f.w.Write(line)
	}
}

// problem is a failure ctl can explain.
type problem int

const (
	problemUnknown problem = iota
	problemAuth
	problemTooManyKeys
	problemTimeout
	problemRefused
	problemNoRoute
	problemUnresolved
	problemHostKeyChanged
	problemClosed
	problemNoDocker
	problemDockerDenied
	problemDockerDown
)

var reNoDocker = regexp.MustCompile(`docker: (command )?not found`)

// classify recognises a failure from ssh's exit code and what it and the
// remote command printed. Exit code 255 is ssh's own; anything else came
// from the command on the edge.
func classify(code int, output string) problem {
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(output, s) {
				return true
			}
		}
		return false
	}
	if code == 255 {
		switch {
		case has("REMOTE HOST IDENTIFICATION HAS CHANGED", "Host key verification failed"):
			return problemHostKeyChanged
		case has("Too many authentication failures"):
			return problemTooManyKeys
		case has("Permission denied ("):
			return problemAuth
		case has("Could not resolve hostname"):
			return problemUnresolved
		case has("Connection timed out", "Operation timed out"):
			return problemTimeout
		case has("Connection refused"):
			return problemRefused
		case has("No route to host", "Network is unreachable"):
			return problemNoRoute
		case has("Connection closed by", "Connection reset by", "kex_exchange_identification"):
			return problemClosed
		}
		return problemUnknown
	}
	lower := strings.ToLower(output)
	switch {
	case strings.Contains(lower, "permission denied while trying to connect to the docker"):
		return problemDockerDenied
	case strings.Contains(lower, "cannot connect to the docker daemon"):
		return problemDockerDown
	case reNoDocker.MatchString(output):
		return problemNoDocker
	}
	return problemUnknown
}

func (c *Client) keyDirName() string {
	if c.KeyDirName != "" {
		return c.KeyDirName
	}
	return c.KeyDir
}

// sshCommand is the plain ssh command a user can run to test the connection.
func (c *Client) sshCommand() string {
	if c.Port != 22 {
		return fmt.Sprintf("ssh -p %d %s", c.Port, c.Target)
	}
	return "ssh " + c.Target
}

// explain turns a recognised problem into a message that says what happened
// and what to try. It returns "" for problems it has nothing to say about.
func (c *Client) explain(p problem) string {
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	settings := fmt.Sprintf("edge.ssh (%s) and edge.ssh_port (%d) in hearthgate.yml", c.Target, c.Port)

	switch p {
	case problemAuth:
		c.explainAuth(&b)

	case problemTooManyKeys:
		line("%s closed the connection after too many keys were tried.", c.host())
		line("Your SSH agent offers more keys than the VPS allows per connection.")
		line("What to try:")
		line("  - put the right key first: ssh-add -D, then ssh-add <the key for this VPS>")
		line("  - or run the command without the agent: env -u SSH_AUTH_SOCK docker compose run --rm ctl ...")

	case problemTimeout, problemNoRoute:
		line("Could not reach %s on port %d: no answer.", c.host(), c.Port)
		line("What to check:")
		line("  - %s", settings)
		line("  - the VPS is running, and its firewall or the provider's security group allows SSH from this network")
		line("  - `%s` works from this machine", c.sshCommand())

	case problemRefused:
		line("%s is reachable, but nothing accepts SSH connections on port %d.", c.host(), c.Port)
		line("What to check:")
		line("  - edge.ssh_port in hearthgate.yml, if the VPS runs SSH on another port")
		line("  - the SSH server is running on the VPS")
		line("  - `%s` works from this machine", c.sshCommand())

	case problemUnresolved:
		line("The name %q could not be resolved, so there is nowhere to connect to.", c.host())
		line("What to check:")
		line("  - the spelling of edge.ssh (%s) in hearthgate.yml", c.Target)
		line("  - DNS works on this machine; an IP address in edge.ssh avoids the lookup")
		line("  - names from ~/.ssh/config are not used: write the real host name or address")

	case problemClosed:
		line("%s accepted the connection on port %d and then closed it before signing in.", c.host(), c.Port)
		line("What to check:")
		line("  - port %d is really SSH, not another service (edge.ssh_port in hearthgate.yml)", c.Port)
		line("  - the VPS is not blocking this address, for example with fail2ban after failed attempts")
		line("  - `%s` works from this machine", c.sshCommand())

	case problemHostKeyChanged:
		line("%s presented a different host key from the one saved on the first connection.", c.host())
		line("ctl stopped before sending anything.")
		line("  - If you reinstalled or replaced the VPS, this is expected: delete %s and run the", c.KnownHosts)
		line("    command again. ctl will show the new key's fingerprint.")
		line("  - If you did not, something may be intercepting the connection. Find out before continuing.")

	case problemNoDocker:
		line("Signed in to %s, but there is no `docker` command for user %q.", c.host(), c.user())
		line("What to try:")
		line("  - install Docker with the Compose plugin on the VPS: https://docs.docker.com/engine/install/")
		line("  - if it is installed, check that `%s docker version` works: the command must be", c.sshCommand())
		line("    on the PATH of a non-interactive shell")

	case problemDockerDenied:
		line("Signed in to %s, but user %q is not allowed to use Docker there.", c.host(), c.user())
		line("What to try, on the VPS:")
		line("  - sudo usermod -aG docker %s    (then sign out and in again for it to take effect)", c.user())
		line("  - or set edge.ssh in hearthgate.yml to a user who can already run `docker ps`")

	case problemDockerDown:
		line("Signed in to %s, but the Docker daemon is not running there.", c.host())
		line("What to try, on the VPS:")
		line("  - sudo systemctl enable --now docker")

	default:
		return ""
	}
	return strings.TrimRight(b.String(), "\n")
}

// explainAuth describes a sign-in the server refused: what ctl had to offer,
// and the likely ways to fix it given that.
func (c *Client) explainAuth(b *strings.Builder) {
	line := func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }
	a := c.auth
	if a == nil {
		a = &authState{dirMissing: true}
	}
	dir := c.keyDirName()
	agent := isSocket(c.AgentSock)
	held := -1
	if agent {
		held = c.agentKeys()
	}
	offered := len(a.keys) > 0 || held > 0

	line("%s refused the sign-in as %q.", c.host(), c.user())
	if offered {
		line("ctl offered:")
	} else {
		line("ctl had no key to offer:")
	}
	for _, k := range a.keys {
		note := ""
		if k.encrypted {
			note = ", protected by a passphrase"
		}
		line("  - %s from %s%s", k.name, dir, note)
	}
	switch {
	case len(a.keys) > 0:
	case a.dirMissing:
		line("  - the key folder %s does not exist", dir)
	case a.dirEmpty:
		line("  - the key folder %s is empty", dir)
	default:
		line("  - %s has no %s (keys with other names are not used)", dir, strings.Join(keyNames, ", "))
	}
	for _, u := range a.unreadable {
		line("  - could not read %s", u)
	}
	switch {
	case held > 0:
		line("  - %d key(s) from your SSH agent", held)
	case held == 0:
		line("  - your SSH agent is running but holds no keys")
	case agent:
		line("  - your SSH agent did not answer")
	default:
		line("  - no SSH agent (SSH_AUTH_SOCK was not set where you ran docker compose)")
	}

	line("What to try:")
	// A folder Docker had to create, or root's own, means the keys are
	// somewhere ctl was not shown. Say so before anything else.
	rootHome := dir == "/root/.ssh" || strings.HasPrefix(dir, "/root/")
	if rootHome && c.Owner != 0 {
		line("  - %s is root's folder. If you ran docker compose with sudo, run it without, or pass your own", dir)
		line("    folder: sudo HEARTHGATE_SSH_DIR=/home/<you>/.ssh docker compose run --rm ctl ...")
	}
	if a.dirEmpty && a.dirRoot && c.Owner != 0 && !rootHome {
		line("  - %s did not exist, so Docker created it, owned by root. Before making a key in it, take it", dir)
		line("    back: sudo chown \"$(id -u):$(id -g)\" %s && chmod 700 %s", dir, dir)
	}
	if len(a.keys) > 0 {
		k := a.keys[0]
		line("  - authorise the key on the VPS: %s", c.copyID(dir+"/"+k.name+".pub"))
		line("    or add the line in %s/%s.pub to ~/.ssh/authorized_keys there, through your provider's console", dir, k.name)
		line("  - check the user in edge.ssh (%s): it must be the account that key signs in to", c.Target)
		for _, k := range a.keys {
			if k.encrypted && held <= 0 {
				line("  - %s needs its passphrase. If you were not asked for it, load the key into an agent first:", k.name)
				line("    eval \"$(ssh-agent)\" && ssh-add %s/%s", dir, k.name)
				break
			}
		}
	} else {
		if held > 0 {
			line("  - authorise one of the agent's keys on the VPS: ssh-copy-id%s %s", c.portFlag(), c.Target)
			line("  - check the user in edge.ssh (%s)", c.Target)
		}
		line("  - if you have no key yet, make one and authorise it on the VPS:")
		line("    ssh-keygen -t ed25519 && %s", c.copyID("~/.ssh/id_ed25519.pub"))
		line("  - if your keys are in another folder: HEARTHGATE_SSH_DIR=/path/to/keys docker compose run --rm ctl ...")
		if held <= 0 {
			line("  - if your key has another name: eval \"$(ssh-agent)\" && ssh-add /path/to/key, then run ctl again")
		}
	}
	line("  - confirm that `%s` signs in from this machine without a password", c.sshCommand())
}

func (c *Client) portFlag() string {
	if c.Port != 22 {
		return fmt.Sprintf(" -p %d", c.Port)
	}
	return ""
}

func (c *Client) copyID(pub string) string {
	return fmt.Sprintf("ssh-copy-id -i %s%s %s", pub, c.portFlag(), c.Target)
}
