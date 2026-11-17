package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/xrvo/hearthgate/internal/config"
	"github.com/xrvo/hearthgate/internal/render"
)

// This file holds the checks that turn a known trap into an explanation
// before ctl acts on it.

// placeholders returns the lines of a config that still hold a value from
// the example `ctl init` writes: its VPS address or its published hostname.
// Keys and a tunnel generated for those would only fail later, at the push.
func placeholders(data []byte) []string {
	example, err := config.Parse(render.ExampleConfig)
	if err != nil {
		return nil
	}
	tokens := []string{example.EdgeAddress}
	for _, p := range example.Publish {
		tokens = append(tokens, p.Hostname)
	}
	var res []*regexp.Regexp
	for _, t := range tokens {
		// A whole value: 203.0.113.5 must not match inside 203.0.113.50.
		res = append(res, regexp.MustCompile(`(^|[^\w.-])`+regexp.QuoteMeta(t)+`($|[^\w.-])`))
	}
	var out []string
	for i, line := range strings.Split(string(data), "\n") {
		text, _, _ := strings.Cut(line, "#")
		for _, re := range res {
			if re.MatchString(text) {
				out = append(out, fmt.Sprintf("line %d: %s", i+1, strings.TrimSpace(text)))
				break
			}
		}
	}
	return out
}

// networkNotes warns about subnet changes. Docker cannot change the subnet of
// a network in place, and cannot replace one that containers are attached to.
func networkNotes(changes []change) []string {
	removed := func(c change, marker string) bool {
		for _, l := range c.lines {
			if strings.HasPrefix(l, "- ") && strings.Contains(l, marker) {
				return true
			}
		}
		return false
	}
	var home []string
	edge := false
	for _, c := range changes {
		switch c.path {
		case render.EnvFile:
			if removed(c, "HEARTHGATE_DMZ_SUBNET=") {
				home = append(home, "hearthgate-dmz")
			}
			if removed(c, "HEARTHGATE_MGMT_SUBNET=") {
				home = append(home, "hearthgate-mgmt")
			}
		case render.EdgeDir + "docker-compose.yml":
			edge = removed(c, "subnet:")
		}
	}
	var out []string
	if len(home) > 0 {
		out = append(out, fmt.Sprintf(`Note: this changes the subnet of %s at home. Docker cannot replace a network
while containers are attached to it, so `+"`docker compose up -d`"+` alone will fail. After applying:
  1. stop the apps and hubs that joined the network
  2. docker compose down && docker compose up -d
  3. start the apps and hubs again`, strings.Join(home, " and ")))
	}
	if edge {
		out = append(out, `Note: this changes the subnet of hearthgate-agents on the edge. Docker cannot replace
a network while containers are attached to it. Stop the agent containers on the VPS first,
or the push will fail; start them again afterwards.`)
	}
	return out
}

// permissionHelp is added to any failure caused by a refused file operation.
// Inside its container ctl is root, so a refusal comes from the host.
const permissionHelp = `
ctl was not allowed to read or write in the project directory. What to check:
  - SELinux (Fedora, RHEL, CentOS): in docker-compose.yml, change the ctl volume ".:/work" to ".:/work:z"
  - rootless Docker or Podman: the directory must belong to you. If part of it was created with sudo:
    sudo chown -R "$(id -u):$(id -g)" .
  - the directory is not on a read-only mount`

func withPermissionHelp(err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("%w\n%s", err, permissionHelp)
	}
	return err
}

// pushedPath records the hash of the edge bundle the last successful push
// installed. It lets ctl say that the edge is behind after a failed push,
// when the generated files themselves already look up to date.
func (a *app) pushedPath() string { return filepath.Join(a.dir, "generated", "edge.pushed") }

func (a *app) markPushed(files render.Files) {
	path := a.pushedPath()
	if err := os.WriteFile(path, []byte(files.WithPrefix(render.EdgeDir).Hash()+"\n"), 0o644); err != nil {
		return
	}
	if uid, gid, ok := dirOwner(a.dir); ok && uid != 0 && os.Geteuid() == 0 {
		os.Chown(path, uid, gid)
	}
}

// edgeBehind reports whether ctl is set up to push but has not pushed this
// bundle.
func (a *app) edgeBehind(cfg *config.Config, files render.Files) bool {
	if cfg.SSH == "" {
		return false
	}
	data, _ := os.ReadFile(a.pushedPath())
	return strings.TrimSpace(string(data)) != files.WithPrefix(render.EdgeDir).Hash()
}

const pushCommand = "docker compose run --rm ctl push"

// afterFailedPush says where both sides stand when the files at home were
// written and the push that should follow did not succeed.
func afterFailedPush(rotated bool) string {
	if rotated {
		return `Where things stand: the new keys are saved at home, and the edge still has the old ones.
The tunnel keeps working for now, because the running home gateway still uses the old keys,
but it will not come back if the gateway restarts. Do not run ` + "`docker compose up -d`" + ` yet.
Once the problem above is fixed, finish the rotation:
  ` + pushCommand + `
  docker compose up -d`
	}
	return `Where things stand: the files at home are updated, and the edge still runs the previous
configuration. Nothing is lost, and ` + "`ctl apply`" + ` will now report nothing to change.
Once the problem above is fixed, send the edge its update:
  ` + pushCommand + `
  docker compose up -d`
}
