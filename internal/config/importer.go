package config

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/eggplants/yamartx/internal/rtx"
)

// FromLines builds a configuration from show config lines.
//
// Lines the schema can express are structured and the rest go to raw, so nothing is lost.
// Afterward, the Render output is checked against the input to confirm that invariant.
// Protected lines are left out of the configuration file.
func FromLines(lines []rtx.Line) (*Config, error) {
	c := &Config{}
	for _, line := range lines {
		if line.Protected() {
			continue
		}
		if !c.absorb(line) {
			c.addRaw(line)
		}
	}

	rendered := map[string]bool{}
	for _, line := range c.Render() {
		rendered[identity(line)] = true
	}
	for _, line := range lines {
		if line.Protected() {
			continue
		}
		if !rendered[identity(line)] {
			return nil, fmt.Errorf("internal error: %q was lost while importing", line.Text)
		}
		delete(rendered, identity(line))
	}
	for extra := range rendered {
		return nil, fmt.Errorf("internal error: import produced a command the router does not have: %q", extra)
	}
	return c, nil
}

func identity(line rtx.Line) string {
	return line.Context + "|" + line.Canonical()
}

func (c *Config) addRaw(line rtx.Line) {
	switch kind, id, _ := strings.Cut(line.Context, " "); kind {
	case "tunnel":
		tunnel := c.Tunnel[id]
		tunnel.Raw = append(tunnel.Raw, line.Text)
		setEntry(&c.Tunnel, id, tunnel)
	case "pp":
		pp := c.PP[id]
		pp.Raw = append(pp.Raw, line.Text)
		setEntry(&c.PP, id, pp)
	default:
		c.Raw.Commands = append(c.Raw.Commands, line.Text)
	}
}

func setEntry[V any](m *map[string]V, key string, value V) {
	if *m == nil {
		*m = map[string]V{}
	}
	(*m)[key] = value
}

func (c *Config) absorb(line rtx.Line) bool {
	fields := strings.Fields(line.Text)
	if len(fields) < 2 {
		return false
	}
	switch kind, id, _ := strings.Cut(line.Context, " "); kind {
	case "tunnel":
		tunnel := c.Tunnel[id]
		ok := absorbTunnel(&tunnel, id, line.Text, fields)
		if ok {
			setEntry(&c.Tunnel, id, tunnel)
		}
		return ok
	case "pp":
		pp := c.PP[id]
		ok := absorbPP(&pp, id, line.Text, fields)
		if ok {
			setEntry(&c.PP, id, pp)
		}
		return ok
	}
	return c.absorbGlobal(line.Text, fields)
}

func absorbTunnel(t *Tunnel, id, text string, f []string) bool {
	switch {
	case len(f) == 3 && f[0] == "tunnel" && f[1] == "encapsulation":
		t.Encapsulation = f[2]
		return true
	case len(f) == 3 && f[0] == "tunnel" && f[1] == "enable" && f[2] == id:
		t.Enable = true
		return true
	}
	return absorbIface(&t.Iface, "tunnel", text, f)
}

func absorbPP(p *PP, id, text string, f []string) bool {
	if len(f) == 3 && f[0] == "pp" && f[1] == "enable" && f[2] == id {
		p.Enable = true
		return true
	}
	return absorbIface(&p.Iface, "pp", text, f)
}

// absorbIface takes in the common settings of the interface given by name.
func absorbIface(i *Iface, name, text string, f []string) bool {
	rest := func(n int) string { return strings.SplitN(text, " ", n+1)[n] }

	if f[0] == "description" && f[1] == name && len(f) >= 3 {
		i.Description = rest(2)
		return true
	}
	if (f[0] != "ip" && f[0] != "ipv6") || f[1] != name || len(f) < 4 {
		return false
	}
	switch {
	case f[0] == "ip" && f[2] == "address":
		i.IPAddress = rest(3)
	case f[0] == "ipv6" && f[2] == "address" && len(f) == 4:
		i.IPv6Address = append(i.IPv6Address, f[3])
	case f[0] == "ipv6" && f[2] == "rtadv" && f[3] == "send" && len(f) >= 5:
		i.IPv6RtadvSend = rest(4)
	case f[0] == "ipv6" && f[2] == "dhcp" && f[3] == "service" && len(f) >= 5:
		i.IPv6DHCPService = rest(4)
	case f[0] == "ip" && f[2] == "mtu" && len(f) == 4:
		mtu, err := strconv.Atoi(f[3])
		if err != nil {
			return false
		}
		i.IPMTU = mtu
	case f[0] == "ip" && f[2] == "nat" && f[3] == "descriptor" && len(f) >= 5:
		i.IPNATDescriptor = rest(4)
	case f[2] == "secure" && f[3] == "filter" && len(f) >= 6:
		target := &i.IPSecureFilter
		if f[0] == "ipv6" {
			target = &i.IPv6SecureFilter
		}
		return absorbSecureFilter(target, f[4], f[5:])
	default:
		return false
	}
	return true
}

func absorbSecureFilter(target **SecureFilter, direction string, f []string) bool {
	var ids, dynamic []int
	current := &ids
	for _, token := range f {
		if token == "dynamic" && current == &ids {
			current = &dynamic
			continue
		}
		id, err := strconv.Atoi(token)
		if err != nil {
			return false // The name form and ranges go to raw
		}
		*current = append(*current, id)
	}
	if *target == nil {
		*target = &SecureFilter{}
	}
	switch direction {
	case "in":
		(*target).In, (*target).InDynamic = ids, dynamic
	case "out":
		(*target).Out, (*target).OutDynamic = ids, dynamic
	default:
		return false
	}
	return true
}

func (c *Config) absorbGlobal(text string, f []string) bool {
	n := len(f)

	switch f[0] {
	case "console":
		if n != 3 {
			return false
		}
		switch f[1] {
		case "character":
			c.System.ConsoleCharacter = f[2]
		case "lines":
			c.System.ConsoleLines = f[2]
		case "columns":
			c.System.ConsoleColumns = f[2]
		default:
			return false
		}
		return true

	case "statistics":
		if n != 3 {
			return false
		}
		setEntry(&c.System.Statistics, f[1], f[2])
		return true

	case "user":
		return f[1] == "attribute" && c.absorbUserAttribute(text, f[2:])

	case "sshd":
		return absorbService(&c.Sshd, text, f)
	case "telnetd":
		return absorbService(&c.Telnetd, text, f)
	case "httpd":
		return absorbService(&c.Httpd, text, f)

	case "ip", "ipv6":
		return c.absorbIPCommand(text, f)

	case "description":
		return c.absorbNamedIface(f[1], text, f)

	case "ngn":
		if n == 4 && f[1] == "type" && ifaceRe.MatchString(f[2]) {
			iface := c.Interface[f[2]]
			iface.NgnType = f[3]
			setEntry(&c.Interface, f[2], iface)
			return true
		}
		return false

	case "nat":
		return c.absorbNAT(text, f)
	case "dhcp":
		return c.absorbDHCP(text, f)
	case "dns":
		return c.absorbDNS(text, f)
	}
	return false
}

func (c *Config) absorbNamedIface(name, text string, f []string) bool {
	if !ifaceRe.MatchString(name) {
		return false
	}
	iface := c.Interface[name]
	if !absorbIface(&iface.Iface, name, text, f) {
		return false
	}
	setEntry(&c.Interface, name, iface)
	return true
}

func absorbService(s *Service, text string, f []string) bool {
	if len(f) < 3 {
		return false
	}
	switch f[1] {
	case "service":
		if len(f) != 3 {
			return false
		}
		s.Service = f[2]
	case "host":
		s.Host = strings.SplitN(text, " ", 3)[2]
	default:
		return false
	}
	return true
}

func (c *Config) absorbUserAttribute(text string, f []string) bool {
	name := AnonymousUser
	if len(f) > 0 && !strings.Contains(f[0], "=") {
		name = f[0]
		f = f[1:]
		if name == AnonymousUser {
			return false // Collides with the anonymous user key, so it goes to raw
		}
	}
	var attr UserAttribute
	for _, pair := range f {
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			return false
		}
		switch key {
		case "administrator":
			attr.Administrator = value
		case "connection":
			attr.Connection = strings.Split(value, ",")
		case "gui-page":
			attr.GUIPage = strings.Split(value, ",")
		case "host":
			attr.Host = value
		case "multi-session":
			attr.MultiSession = value
		case "login-timer":
			timer, err := strconv.Atoi(value)
			if err != nil {
				return false
			}
			attr.LoginTimer = timer
		default:
			return false
		}
	}
	if renderUserAttribute(name, attr) != text {
		return false // An unexpected attribute order would become a permanent diff in string comparison
	}
	setEntry(&c.UserAttribute, name, attr)
	return true
}

func familyOf(c *Config, name string) *IPFamily {
	if name == "ip" {
		return &c.IP
	}
	return &c.IPv6.IPFamily
}

func (c *Config) absorbIPCommand(text string, f []string) bool {
	family := familyOf(c, f[0])
	switch f[1] {
	case "filter":
		if len(f) > 2 && f[2] == "dynamic" {
			return absorbDynamicFilter(family, text, f)
		}
		return absorbFilter(family, f)
	case "route":
		if len(f) < 4 {
			return false
		}
		setEntry(&family.Route, f[2], strings.SplitN(text, " ", 4)[3])
		return true
	case "prefix":
		if f[0] == "ipv6" && len(f) >= 4 && numericRe.MatchString(f[2]) {
			setEntry(&c.IPv6.Prefix, f[2], strings.SplitN(text, " ", 4)[3])
			return true
		}
		return false
	}
	return c.absorbNamedIface(f[1], text, f)
}

func wildcardToEmpty(value string) string {
	if value == "*" {
		return ""
	}
	return value
}

func absorbFilter(family *IPFamily, f []string) bool {
	// <ip|ipv6> filter <id> <action> <src> [<dst> [<proto> [<src_port> [<dst_port>]]]]
	if len(f) < 5 || len(f) > 9 || !numericRe.MatchString(f[2]) || !actionRe.MatchString(f[3]) {
		return false
	}
	field := func(i int) string {
		if i < len(f) {
			return wildcardToEmpty(f[i])
		}
		return ""
	}
	setEntry(&family.Filter, f[2], Filter{
		Action:  f[3],
		Src:     field(4),
		Dst:     field(5),
		Proto:   field(6),
		SrcPort: field(7),
		DstPort: field(8),
	})
	return true
}

func absorbDynamicFilter(family *IPFamily, text string, f []string) bool {
	// <ip|ipv6> filter dynamic <id> <src> <dst> <proto> [option...]
	if len(f) < 7 || !numericRe.MatchString(f[3]) || f[6] == "filter" {
		return false // The filter ... form goes to raw
	}
	entry := DynamicFilter{Src: wildcardToEmpty(f[4]), Dst: wildcardToEmpty(f[5]), Proto: f[6]}
	if len(f) > 7 {
		entry.Options = strings.SplitN(text, " ", 8)[7]
	}
	setEntry(&family.FilterDynamic, f[3], entry)
	return true
}

func (c *Config) absorbNAT(text string, f []string) bool {
	if len(f) < 5 || f[1] != "descriptor" {
		return false
	}
	switch {
	case f[2] == "type" && numericRe.MatchString(f[3]):
		entry := c.NAT[f[3]]
		entry.Type = strings.SplitN(text, " ", 5)[4]
		setEntry(&c.NAT, f[3], entry)
	case f[2] == "address" && f[3] == "outer" && len(f) >= 6 && numericRe.MatchString(f[4]):
		entry := c.NAT[f[4]]
		entry.AddressOuter = strings.SplitN(text, " ", 6)[5]
		setEntry(&c.NAT, f[4], entry)
	default:
		return false
	}
	return true
}

var macRe = regexp.MustCompile(`^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$`)

func (c *Config) absorbDHCP(text string, f []string) bool {
	switch {
	case len(f) == 3 && f[1] == "service":
		c.DHCP.Service = f[2]
	case len(f) >= 5 && f[1] == "server" && f[2] == "rfc2131" && f[3] == "compliant":
		c.DHCP.RFC2131Compliant = strings.SplitN(text, " ", 5)[4]
	case len(f) == 7 && f[1] == "scope" && f[2] == "bind" && f[5] == "ethernet" && macRe.MatchString(f[6]):
		scope := c.DHCP.Scope[f[3]]
		scope.Binds = append(scope.Binds, Bind{IP: f[4], MAC: f[6]})
		setEntry(&c.DHCP.Scope, f[3], scope)
	case len(f) >= 5 && f[1] == "scope" && f[2] == "option":
		scope := c.DHCP.Scope[f[3]]
		scope.Options = strings.SplitN(text, " ", 5)[4]
		setEntry(&c.DHCP.Scope, f[3], scope)
	case len(f) >= 4 && f[1] == "scope" && numericRe.MatchString(f[2]):
		scope := c.DHCP.Scope[f[2]]
		scope.Range = strings.SplitN(text, " ", 4)[3]
		setEntry(&c.DHCP.Scope, f[2], scope)
	default:
		return false
	}
	return true
}

func (c *Config) absorbDNS(text string, f []string) bool {
	switch {
	case len(f) >= 3 && f[1] == "host":
		c.DNS.Host = strings.SplitN(text, " ", 3)[2]
	case len(f) == 4 && f[1] == "service" && f[2] == "fallback":
		c.DNS.ServiceFallback = f[3]
	case len(f) >= 4 && f[1] == "server" && f[2] == "dhcp":
		c.DNS.ServerDHCP = strings.SplitN(text, " ", 4)[3]
	case len(f) >= 5 && f[1] == "server" && f[2] == "select" && numericRe.MatchString(f[3]):
		setEntry(&c.DNS.ServerSelect, f[3], strings.SplitN(text, " ", 5)[4])
	case len(f) == 5 && f[1] == "private" && f[2] == "address" && f[3] == "spoof":
		c.DNS.PrivateAddressSpoof = f[4]
	case (len(f) == 5 || len(f) == 6) && f[1] == "static":
		record := StaticRecord{Type: f[2], Name: f[3], Value: f[4]}
		if len(f) == 6 {
			ttl, ok := strings.CutPrefix(f[5], "ttl=")
			if !ok {
				return false
			}
			value, err := strconv.Atoi(ttl)
			if err != nil {
				return false
			}
			record.TTL = value
		}
		c.DNS.Static = append(c.DNS.Static, record)
	default:
		return false
	}
	return true
}
