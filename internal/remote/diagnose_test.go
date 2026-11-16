package remote

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		code   int
		output string
		want   problem
	}{
		{255, "ubuntu@203.0.113.5: Permission denied (publickey).", problemAuth},
		{255, "Received disconnect from 203.0.113.5 port 22:2: Too many authentication failures", problemTooManyKeys},
		{255, "ssh: connect to host 203.0.113.5 port 22: Connection timed out", problemTimeout},
		{255, "ssh: connect to host 203.0.113.5 port 2222: Connection refused", problemRefused},
		{255, "ssh: connect to host 203.0.113.5 port 22: No route to host", problemNoRoute},
		{255, "ssh: Could not resolve hostname vps.example: Name does not resolve", problemUnresolved},
		{255, "@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @\nHost key verification failed.", problemHostKeyChanged},
		{255, "kex_exchange_identification: Connection closed by remote host", problemClosed},
		{255, "something new", problemUnknown},
		{127, "sh: 5: docker: not found", problemNoDocker},
		{127, "bash: line 5: docker: command not found", problemNoDocker},
		{1, "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock", problemDockerDenied},
		{1, "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?", problemDockerDown},
		// A remote command's output must not be mistaken for an ssh failure.
		{1, "Permission denied (publickey).", problemUnknown},
		{1, "Error response from daemon: port is already allocated", problemUnknown},
	}
	for _, c := range cases {
		if got := classify(c.code, c.output); got != c.want {
			t.Errorf("classify(%d, %q) = %d, want %d", c.code, c.output, got, c.want)
		}
	}
}

// opensshKey builds the start of an OpenSSH private key file with the given cipher.
func opensshKey(cipher string) []byte {
	raw := []byte("openssh-key-v1\x00")
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(cipher)))
	raw = append(raw, cipher...)
	raw = append(raw, "the rest of the key"...)
	return []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n" + base64.StdEncoding.EncodeToString(raw) + "\n-----END OPENSSH PRIVATE KEY-----\n")
}

func TestEncrypted(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"openssh plain", opensshKey("none"), false},
		{"openssh with passphrase", opensshKey("aes256-ctr"), true},
		{"pem plain", []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n"), false},
		{"pem with passphrase", []byte("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\nMIIE\n-----END RSA PRIVATE KEY-----\n"), true},
		{"pkcs8 with passphrase", []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIE\n-----END ENCRYPTED PRIVATE KEY-----\n"), true},
		{"not a key", []byte("hello"), false},
	}
	for _, c := range cases {
		if got := encrypted(c.data); got != c.want {
			t.Errorf("%s: encrypted = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestFingerprint(t *testing.T) {
	// SHA-256 of "abc" is a published test vector.
	kind, fp, ok := fingerprint("[vps.example]:2222 ssh-ed25519 YWJj")
	if !ok || kind != "ed25519" || fp != "SHA256:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0" {
		t.Errorf("fingerprint = %q %q %v", kind, fp, ok)
	}
	for _, line := range []string{"", "# comment line here", "host ssh-ed25519 not*base64"} {
		if _, _, ok := fingerprint(line); ok {
			t.Errorf("fingerprint(%q) succeeded", line)
		}
	}
}

func TestLineFilter(t *testing.T) {
	var out bytes.Buffer
	f := &lineFilter{w: &out, drop: "Warning: Permanently added"}
	for _, chunk := range []string{"Warning: Perman", "ently added 'h' (ED25519).\nPermission ", "denied (publickey).\nlast"} {
		f.Write([]byte(chunk))
	}
	f.Flush()
	if got, want := out.String(), "Permission denied (publickey).\nlast"; got != want {
		t.Errorf("filtered output = %q, want %q", got, want)
	}
}

func TestAnnounceHostKeys(t *testing.T) {
	known := filepath.Join(t.TempDir(), "known_hosts")
	before := []byte("other ssh-ed25519 eHl6\n")
	os.WriteFile(known, append(before, "203.0.113.5 ssh-ed25519 YWJj\n"...), 0o600)
	var out bytes.Buffer
	c := &Client{Target: "ubuntu@203.0.113.5", Port: 22, KnownHosts: known, Stderr: &out}
	c.announceHostKeys(before)
	for _, want := range []string{"First connection to 203.0.113.5", "SHA256:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0", "ssh_host_ed25519_key.pub"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("announcement lacks %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	after, _ := os.ReadFile(known)
	c.announceHostKeys(after)
	if out.Len() != 0 {
		t.Errorf("a known host was announced again:\n%s", out.String())
	}
}

func explainAuth(t *testing.T, c *Client) string {
	t.Helper()
	if _, err := c.identities(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c.explain(problemAuth)
}

func wantAll(t *testing.T, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("message lacks %q:\n%s", w, got)
		}
	}
}

func TestExplainAuthWithoutKeys(t *testing.T) {
	c := &Client{Target: "ubuntu@203.0.113.5", Port: 22, KeyDir: t.TempDir(), KeyDirName: "/home/me/.ssh", Owner: 1000}
	msg := explainAuth(t, c)
	wantAll(t, msg,
		`203.0.113.5 refused the sign-in as "ubuntu"`,
		"ctl had no key to offer",
		"the key folder /home/me/.ssh is empty",
		"no SSH agent",
		"ssh-keygen -t ed25519 && ssh-copy-id -i ~/.ssh/id_ed25519.pub ubuntu@203.0.113.5",
		"HEARTHGATE_SSH_DIR=",
		"`ssh ubuntu@203.0.113.5`",
	)
	if strings.Contains(msg, "root's folder") {
		t.Errorf("sudo hint shown for a user's own folder:\n%s", msg)
	}
}

func TestExplainAuthMissingFolderAndSudo(t *testing.T) {
	c := &Client{Target: "ubuntu@203.0.113.5", Port: 22, KeyDir: filepath.Join(t.TempDir(), "none"), KeyDirName: "/root/.ssh", Owner: 1000}
	wantAll(t, explainAuth(t, c),
		"the key folder /root/.ssh does not exist",
		"/root/.ssh is root's folder",
		"sudo HEARTHGATE_SSH_DIR=",
	)
}

func TestExplainAuthWithKeys(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "id_ed25519"), opensshKey("aes256-ctr"), 0o600)
	os.WriteFile(filepath.Join(dir, "work_key"), opensshKey("none"), 0o600)
	c := &Client{Target: "ubuntu@203.0.113.5", Port: 2222, KeyDir: dir, KeyDirName: "/home/me/.ssh", Owner: 1000}
	msg := explainAuth(t, c)
	wantAll(t, msg,
		"ctl offered:",
		"id_ed25519 from /home/me/.ssh, protected by a passphrase",
		"ssh-copy-id -i /home/me/.ssh/id_ed25519.pub -p 2222 ubuntu@203.0.113.5",
		"ssh-add /home/me/.ssh/id_ed25519",
		"check the user in edge.ssh (ubuntu@203.0.113.5)",
		"`ssh -p 2222 ubuntu@203.0.113.5`",
	)
	if strings.Contains(msg, "work_key") {
		t.Errorf("a key with a non-standard name was offered:\n%s", msg)
	}
}

func TestExplainOtherProblems(t *testing.T) {
	c := &Client{Target: "ubuntu@vps.example", Port: 2222, KnownHosts: "generated/known_hosts"}
	cases := map[problem][]string{
		problemTimeout:        {"Could not reach vps.example on port 2222", "edge.ssh_port (2222)", "security group"},
		problemRefused:        {"nothing accepts SSH connections on port 2222", "edge.ssh_port"},
		problemUnresolved:     {`"vps.example" could not be resolved`, "~/.ssh/config"},
		problemHostKeyChanged: {"different host key", "delete generated/known_hosts", "intercepting"},
		problemNoDocker:       {"no `docker` command", "docs.docker.com"},
		problemDockerDenied:   {"not allowed to use Docker", "sudo usermod -aG docker ubuntu"},
		problemDockerDown:     {"daemon is not running", "systemctl"},
		problemTooManyKeys:    {"too many keys", "ssh-add -D"},
		problemClosed:         {"closed it before signing in", "fail2ban"},
	}
	for p, wants := range cases {
		wantAll(t, c.explain(p), wants...)
	}
	if msg := c.explain(problemUnknown); msg != "" {
		t.Errorf("explain(unknown) = %q", msg)
	}
}
