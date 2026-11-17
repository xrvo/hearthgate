package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// This file holds how ctl talks: colour, the summary before a diff, and the
// "Next:" block that ends a command.

// errCancelled means the user answered no. It is not reported as an error.
var errCancelled = errors.New("cancelled")

const (
	bold   = "1"
	dim    = "2"
	red    = "31"
	green  = "32"
	yellow = "33"
)

// useColor reports whether output to w should be coloured: only on a
// terminal, and never when NO_COLOR is set (https://no-color.org).
func useColor(w io.Writer) bool {
	return isTerminal(w) && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
}

func (a *app) paint(code, s string) string {
	if !a.color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// step is one thing for the user to do next.
type step struct {
	cmd string
	why string
}

const (
	cmdUp    = "docker compose up -d"
	cmdCheck = "docker compose run --rm ctl check"
	cmdApply = "docker compose run --rm ctl apply"
)

// next ends a command with the exact commands to run from here.
func (a *app) next(steps ...step) {
	if len(steps) == 0 {
		return
	}
	width := 0
	for _, s := range steps {
		if len(s.cmd) <= 60 {
			width = max(width, len(s.cmd))
		}
	}
	fmt.Fprintf(a.out, "\n%s\n", a.paint(bold, "Next:"))
	for _, s := range steps {
		if len(s.cmd) > 60 {
			// Too long to sit beside its explanation.
			fmt.Fprintf(a.out, "  %s\n    %s\n", a.paint(dim, "# "+s.why), s.cmd)
			continue
		}
		fmt.Fprintf(a.out, "  %-*s  %s\n", width, s.cmd, a.paint(dim, "# "+s.why))
	}
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// summarize says, before the diff, which side each change lands on and what
// applying it interrupts.
func (a *app) summarize(changes []change) {
	edge, home := 0, 0
	for _, c := range changes {
		if strings.HasPrefix(c.path, "generated/edge/") {
			edge++
		} else {
			home++
		}
	}
	fmt.Fprintf(a.out, "This changes %s:\n", plural(len(changes), "generated file"))
	if edge > 0 {
		fmt.Fprintf(a.out, "  edge  %s. The edge restarts when it receives them, and open connections drop for a moment.\n", plural(edge, "file"))
	}
	if home > 0 {
		fmt.Fprintf(a.out, "  home  %s. The gateway restarts on `%s`, and open connections drop for a moment.\n", plural(home, "file"), cmdUp)
	}
}

func (a *app) printChanges(changes []change) {
	a.summarize(changes)
	for _, c := range changes {
		fmt.Fprintf(a.out, "\n%s\n", a.paint(bold, c.path))
		for _, l := range c.lines {
			switch {
			case strings.HasPrefix(l, "+"):
				l = a.paint(green, l)
			case strings.HasPrefix(l, "-"):
				l = a.paint(red, l)
			}
			fmt.Fprintf(a.out, "  %s\n", l)
		}
	}
	fmt.Fprintln(a.out)
}
