package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/xrvo/hearthgate/internal/config"
	"github.com/xrvo/hearthgate/internal/render"
)

// answers is what the first `init` asks for: enough for a working tunnel
// with one published hostname.
type answers struct {
	address string
	sshUser string // empty: the user installs the edge by hand
	host    string
	target  string
}

func (w answers) ssh() string {
	if w.sshUser == "" || strings.Contains(w.sshUser, "@") {
		return w.sshUser // nothing, or a full user@host
	}
	return w.sshUser + "@" + w.address
}

// problem returns what config.Parse says about these answers, limited to the
// lines that mention field. Values are marshalled, so an answer cannot break
// out of its place in the document.
func (w answers) problem(field string) string {
	edge := map[string]any{"address": w.address}
	if w.sshUser != "" {
		edge["ssh"] = w.ssh()
	}
	doc, err := yaml.Marshal(map[string]any{"edge": edge, "publish": map[string]string{w.host: w.target}})
	if err != nil {
		return err.Error()
	}
	_, err = config.Parse(doc)
	if err == nil {
		return ""
	}
	var lines []string
	for _, l := range strings.Split(err.Error(), "\n") {
		if strings.Contains(l, field) {
			lines = append(lines, l)
		}
	}
	return strings.Join(lines, "\n")
}

// interview asks the questions. It returns errNoAnswer, having asked nothing
// that was answered, when there is nobody to ask.
func (a *app) interview() (*answers, error) {
	// Stand-ins that are valid, so each answer is judged on its own.
	w := &answers{address: "192.0.2.1", host: "a.example.org", target: "a:1"}
	fmt.Fprintf(a.out, "There is no %s yet. Four questions will write one; press Ctrl-C to stop.\n\n", filepath.Base(a.cfgPath))

	questions := []struct {
		prompt string
		field  string
		set    func(string)
		empty  string // what to say when the answer may not be empty
	}{
		{"Public IP address or hostname of your VPS: ", "edge.address", func(s string) { w.address = s }, "the VPS address is needed: it is where home connects to"},
		{"SSH user on the VPS that can run docker, such as root or ubuntu\n(leave empty to install the edge yourself): ", "edge.ssh", func(s string) { w.sshUser = s }, ""},
		{"First hostname to publish, such as photos.yourdomain.com: ", "publish", func(s string) { w.host = strings.ToLower(s) }, "a hostname is needed: it is the public name of your service"},
		{"Home container and port it should reach, such as immich-server:2283: ", "publish", func(s string) { w.target = s }, "a target is needed, as container:port"},
	}
	for i, q := range questions {
		for {
			answer, err := a.ask(q.prompt)
			if err != nil {
				if errors.Is(err, errNoAnswer) && i > 0 {
					return nil, errCancelled
				}
				return nil, err
			}
			if answer == "" && q.empty != "" {
				fmt.Fprintf(a.out, "  %s\n", q.empty)
				continue
			}
			q.set(answer)
			if p := w.problem(q.field); p != "" {
				fmt.Fprintf(a.out, "  %s\n", p)
				continue
			}
			break
		}
	}
	return w, nil
}

// document renders the answers as a hearthgate.yml, with the example's notes
// on what else can be set.
func (w answers) document() []byte {
	var b bytes.Buffer
	b.WriteString("# Hearthgate configuration. This file lives on your home server only;\n")
	b.WriteString("# it is never sent to the edge.\n")
	b.WriteString("# After changing it: docker compose run --rm ctl deploy && docker compose up -d\n\n")
	fmt.Fprintf(&b, "edge:\n  address: %s\n", w.address)
	if w.sshUser != "" {
		fmt.Fprintf(&b, "  ssh: %s\n", w.ssh())
	} else {
		fmt.Fprintf(&b, "  # ssh: user@%s   # lets ctl install, start and check the edge for you\n", w.address)
	}
	b.WriteString("\n# Public hostname -> home container:port (the container must join hearthgate-dmz)\n")
	fmt.Fprintf(&b, "publish:\n  %s: %s\n\n", w.host, w.target)
	b.WriteString(`# Name -> edge container:port (the container must join hearthgate-agents).
# Home hubs on hearthgate-mgmt reach each one at gateway:<port>.
# agents:
#   beszel: beszel-agent:45876
#   # Long form, for when the port is taken (80, 443, 2019) or used by another agent:
#   exporter:
#     target: node-exporter:9100
#     listen: 19100

`)
	// The example ends with the optional settings and their defaults.
	const marker = "# Optional settings"
	if i := bytes.Index(render.ExampleConfig, []byte(marker)); i >= 0 {
		b.Write(render.ExampleConfig[i:])
	}
	return b.Bytes()
}

// writeConfig stores a new hearthgate.yml, owned like the project directory.
func (a *app) writeConfig(content []byte) error {
	if err := os.WriteFile(a.cfgPath, content, 0o644); err != nil {
		return err
	}
	if uid, gid, ok := dirOwner(a.dir); ok && uid != 0 && os.Geteuid() == 0 {
		os.Chown(a.cfgPath, uid, gid)
	}
	return nil
}
