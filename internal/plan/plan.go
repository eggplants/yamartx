// Package plan computes the difference between the router's configuration and the declared one.
package plan

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/eggplants/yamartx/internal/rtx"
)

// Action is the kind of a difference.
type Action string

// The kinds of difference. The values double as the symbols shown in output.
const (
	Add    Action = "+"
	Change Action = "~"
	Remove Action = "-"
)

// Item is one difference.
type Item struct {
	Action  Action
	Context string
	Old     rtx.Line
	New     rtx.Line
}

// command returns the router command that applies the Item.
func (i Item) command() string {
	if i.Action == Remove {
		return i.Old.NoForm()
	}
	return i.New.Text
}

// Plan is a list of differences. Items are in execution order.
type Plan struct {
	Items []Item
	// Protected lists the router lines excluded from comparison.
	Protected []rtx.Line
}

// Empty reports whether there are no differences.
func (p *Plan) Empty() bool { return len(p.Items) == 0 }

func id(l rtx.Line) string { return l.Context + "|" + l.Key() }

// Diff builds a plan that brings current (the router) in line with desired (the configuration file).
func Diff(current, desired []rtx.Line) (*Plan, error) {
	p := &Plan{}
	currentByID := map[string]rtx.Line{}
	for _, line := range current {
		if line.Protected() {
			p.Protected = append(p.Protected, line)
			continue
		}
		currentByID[id(line)] = line
	}

	desiredByID := map[string]rtx.Line{}
	var applies, removes []Item
	for _, line := range desired {
		if line.Protected() {
			return nil, fmt.Errorf("%q is read-only and cannot be managed", line.Text)
		}
		key := id(line)
		if prev, dup := desiredByID[key]; dup {
			if prev.Canonical() != line.Canonical() {
				return nil, fmt.Errorf("conflicting settings for %q: %q and %q", line.Key(), prev.Text, line.Text)
			}
			continue
		}
		desiredByID[key] = line

		old, exists := currentByID[key]
		switch {
		case !exists:
			applies = append(applies, Item{Action: Add, Context: line.Context, New: line})
		case old.Canonical() != line.Canonical():
			applies = append(applies, Item{Action: Change, Context: line.Context, Old: old, New: line})
		}
	}
	for _, line := range current {
		if line.Protected() {
			continue
		}
		if _, keep := desiredByID[id(line)]; !keep {
			removes = append(removes, Item{Action: Remove, Context: line.Context, Old: line})
		}
	}

	// Send definitions before references, and do removals last in reverse order. New filters
	// then take effect before old ones go away, so protection never lapses midway.
	sort.SliceStable(applies, func(i, j int) bool {
		a, b := applies[i], applies[j]
		ra, rb := rank(a.New), rank(b.New)
		if ra.major != rb.major {
			return ra.major < rb.major
		}
		if a.Context != b.Context {
			return a.Context < b.Context
		}
		return ra.minor < rb.minor
	})
	sort.SliceStable(removes, func(i, j int) bool {
		a, b := removes[i], removes[j]
		ra, rb := rank(a.Old), rank(b.Old)
		if ra.major != rb.major {
			return ra.major > rb.major
		}
		if a.Context != b.Context {
			return a.Context < b.Context
		}
		return ra.minor > rb.minor
	})
	p.Items = append(applies, removes...)
	return p, nil
}

type order struct{ major, minor int }

// rank returns the order to send a command in, based on its dependencies.
func rank(l rtx.Line) order {
	f := strings.Fields(l.Text)
	second := ""
	if len(f) > 1 {
		second = f[1]
	}
	if l.Context != "" {
		switch {
		case f[0] == "tunnel" && second == "encapsulation":
			return order{50, 0}
		case (f[0] == "tunnel" || f[0] == "pp") && second == "enable":
			return order{50, 2}
		}
		return order{50, 1}
	}
	isIP := f[0] == "ip" || f[0] == "ipv6"
	switch {
	case isIP && second == "filter":
		return order{10, 0}
	case f[0] == "nat":
		return order{20, 0}
	case f[0] == "ipv6" && second == "prefix":
		return order{25, 0}
	case f[0] == "dhcp" && second == "scope":
		if len(f) > 2 && (f[2] == "bind" || f[2] == "option") {
			return order{30, 1}
		}
		return order{30, 0}
	case f[0] == "dhcp":
		return order{29, 0}
	case f[0] == "dns":
		return order{40, 0}
	case isIP && second == "route":
		return order{60, 0}
	case isIP || f[0] == "description" || f[0] == "ngn":
		return order{50, 1}
	}
	return order{}
}

// Commands returns the commands that carry out the plan.
func (p *Plan) Commands() []string {
	var commands []string
	context := ""
	for _, item := range p.Items {
		if item.Context != context {
			if context != "" {
				commands = append(commands, rtx.DeselectCommand(context))
			}
			if item.Context != "" {
				commands = append(commands, rtx.SelectCommand(item.Context))
			}
			context = item.Context
		}
		commands = append(commands, item.command())
	}
	if context != "" {
		commands = append(commands, rtx.DeselectCommand(context))
	}
	return commands
}

// lockoutRe matches settings that could prevent reconnecting over SSH if they go wrong.
var lockoutRe = regexp.MustCompile(`^(sshd |security class|user attribute|lan |vlan |ethernet |(ip|ipv6) (lan|vlan|bridge)\S* (address|secondary address|secure filter))`)

// LockoutRisks returns the differences that could cut off remote access.
func (p *Plan) LockoutRisks() []Item {
	var risks []Item
	for _, item := range p.Items {
		line := item.New
		if item.Action == Remove {
			line = item.Old
		}
		if lockoutRe.MatchString(line.Text) {
			risks = append(risks, item)
		}
	}
	return risks
}

// Summary returns a summary of the counts.
func (p *Plan) Summary() string {
	counts := map[Action]int{}
	for _, item := range p.Items {
		counts[item.Action]++
	}
	return fmt.Sprintf("Plan: %d to add, %d to change, %d to remove.", counts[Add], counts[Change], counts[Remove])
}

const (
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
	ansiReset  = "\x1b[0m"
)

// Write prints the differences in a format similar to terraform plan.
func (p *Plan) Write(w io.Writer, color bool) {
	paint := func(code, text string) string {
		if color {
			return code + text + ansiReset
		}
		return text
	}
	prefix := func(context string) string {
		if context == "" {
			return ""
		}
		return "[" + context + "] "
	}
	for _, item := range p.Items {
		switch item.Action {
		case Add:
			fmt.Fprintln(w, paint(ansiGreen, "  + "+prefix(item.Context)+item.New.Text))
		case Change:
			fmt.Fprintln(w, paint(ansiYellow, "  ~ "+prefix(item.Context)+item.Old.Text))
			fmt.Fprintln(w, paint(ansiYellow, "    => "+item.New.Text))
		case Remove:
			fmt.Fprintln(w, paint(ansiRed, "  - "+prefix(item.Context)+item.Old.Text))
		}
	}
	if !p.Empty() {
		fmt.Fprintln(w)
	}
}
