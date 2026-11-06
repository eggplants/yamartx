// Package rtx handles the configuration lines of Yamaha RTX routers.
//
// It represents a show config line as a context (such as tunnel 1) plus a command string,
// and provides the identity key, no form and protection check that diffing needs.
package rtx

import (
	"regexp"
	"strings"
)

// Line represents one configuration line. Context is empty for global lines,
// and otherwise has a form like "tunnel 1" or "pp anonymous".
type Line struct {
	Context string
	Text    string
}

var selectRe = regexp.MustCompile(`^(tunnel|pp) select (\S+)$`)

// ParseShowConfig converts show config output into a list of lines.
// Comment lines are dropped, and indented lines after tunnel select or pp select belong to that context.
func ParseShowConfig(text string) []Line {
	var lines []Line
	context := ""
	for raw := range strings.Lines(text) {
		raw = strings.TrimRight(raw, " \t\r\n")
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := selectRe.FindStringSubmatch(trimmed); m != nil {
			context = m[1] + " " + m[2]
			if m[2] == "none" {
				context = ""
			}
			continue
		}
		if !strings.HasPrefix(raw, " ") {
			context = ""
		}
		lines = append(lines, Line{Context: context, Text: trimmed})
	}
	return lines
}

// SelectCommand returns the command that enters a context.
func SelectCommand(context string) string {
	kind, id, _ := strings.Cut(context, " ")
	return kind + " select " + id
}

// DeselectCommand returns the command that leaves a context.
func DeselectCommand(context string) string {
	kind, _, _ := strings.Cut(context, " ")
	return kind + " select none"
}

// keyPatterns is a table of how many tokens determine the identity of a setting.
// Patterns are tried in order, so more specific ones come first. * matches any one token.
// A command that matches none uses its whole line as the key.
//
// A line with the same key but another value can be overwritten by re-sending it, and "no <key>" removes it.
// The no form of each pattern has been checked against Yamaha's command reference.
var keyPatterns = compilePatterns(
	"console character", "console lines", "console columns", "console prompt",

	"ip filter dynamic *", "ip filter *",
	"ipv6 filter dynamic *", "ipv6 filter *",
	"ip route *", "ipv6 route *",
	"ipv6 prefix *",

	"ip * secure filter *", "ipv6 * secure filter *",
	"ip * secondary address", "ip * address",
	"ipv6 * address *", // An IPv6 interface can have multiple addresses
	"ipv6 * rtadv send", "ipv6 * dhcp service",
	"ip * mtu", "ip * nat descriptor",
	"description *",
	"ngn type *",

	"tunnel encapsulation", "tunnel enable *",
	"pp enable *",

	"nat descriptor type *",
	"nat descriptor address outer *", "nat descriptor address inner *",
	"nat descriptor masquerade static * *",

	"dhcp service", "dhcp server rfc2131 compliant",
	"dhcp scope bind * *", "dhcp scope option *", "dhcp scope *",

	"dns host", "dns service fallback", "dns service",
	"dns server dhcp", "dns server select *", "dns server",
	"dns private address spoof", "dns domain",
	"dns static * * *", // A name can have multiple values, so the value is part of the key

	"telnetd service", "telnetd host",
	"httpd service", "httpd host",
	"sshd service", "sshd host key generate", "sshd host",
	"statistics *",
)

func compilePatterns(patterns ...string) [][]string {
	compiled := make([][]string, len(patterns))
	for i, p := range patterns {
		compiled[i] = strings.Fields(p)
	}
	return compiled
}

func matchPattern(pattern, fields []string) bool {
	if len(fields) < len(pattern) {
		return false
	}
	for i, token := range pattern {
		if token != "*" && token != fields[i] {
			return false
		}
	}
	return true
}

// Key returns a string that uniquely identifies the setting within its context.
func (l Line) Key() string {
	fields := strings.Fields(l.Text)
	// user attribute may omit the user name, in which case the third token is an attribute.
	if len(fields) >= 2 && fields[0] == "user" && fields[1] == "attribute" {
		if len(fields) > 2 && !strings.Contains(fields[2], "=") {
			return strings.Join(fields[:3], " ")
		}
		return "user attribute"
	}
	for _, pattern := range keyPatterns {
		if matchPattern(pattern, fields) {
			return strings.Join(fields[:len(pattern)], " ")
		}
	}
	return strings.Join(fields, " ")
}

// NoForm returns the command that removes the setting.
func (l Line) NoForm() string {
	return "no " + l.Key()
}

// Canonical returns the same string for lines with the same meaning. Diffing compares these.
//
// Trailing * in ip filter and ipv6 filter is removed, since omitting it does not change the meaning.
func (l Line) Canonical() string {
	fields := strings.Fields(l.Text)
	if len(fields) > 5 && isFilter(fields) && fields[2] != "dynamic" {
		for len(fields) > 5 && fields[len(fields)-1] == "*" {
			fields = fields[:len(fields)-1]
		}
		return strings.Join(fields, " ")
	}
	return l.Text
}

func isFilter(fields []string) bool {
	return len(fields) >= 2 && (fields[0] == "ip" || fields[0] == "ipv6" || fields[0] == "ethernet") && fields[1] == "filter"
}

// protectedPrefixes lists commands whose values show config masks, or that can only
// be set interactively.
var protectedPrefixes = []string{
	"login password",
	"administrator password",
	"login user",
	"sshd host key generate",
}

// Protected reports whether this tool must treat the line as read-only.
//
// For example, re-sending "login user foo *" as is would change the password to *,
// and sending no because it is absent from the file would block logins. Protected lines are
// therefore neither compared nor changed. Lines ending in * are treated the same way even if
// unlisted, as they may hold masked secrets (except filter lines, where * is ordinary).
func (l Line) Protected() bool {
	for _, prefix := range protectedPrefixes {
		if l.Text == prefix || strings.HasPrefix(l.Text, prefix+" ") {
			return true
		}
	}
	fields := strings.Fields(l.Text)
	return len(fields) > 0 && fields[len(fields)-1] == "*" && !isFilter(fields)
}
