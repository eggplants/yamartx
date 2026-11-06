package config

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/eggplants/yamartx/internal/rtx"
)

// renderer is a small helper that accumulates Lines. Empty values are skipped.
type renderer struct {
	lines   []rtx.Line
	context string
}

func (r *renderer) add(format string, args ...any) {
	r.lines = append(r.lines, rtx.Line{Context: r.context, Text: fmt.Sprintf(format, args...)})
}

func (r *renderer) opt(prefix, value string) {
	if value != "" {
		r.add("%s %s", prefix, value)
	}
}

// Render converts the configuration into command lines.
func (c *Config) Render() []rtx.Line {
	r := &renderer{}

	r.opt("console character", c.System.ConsoleCharacter)
	r.opt("console lines", c.System.ConsoleLines)
	r.opt("console columns", c.System.ConsoleColumns)
	for _, name := range sortedKeys(c.UserAttribute) {
		r.add("%s", renderUserAttribute(name, c.UserAttribute[name]))
	}

	renderFamily(r, "ip", c.IP)
	renderFamily(r, "ipv6", c.IPv6.IPFamily)
	for _, id := range sortedKeys(c.IPv6.Prefix) {
		r.add("ipv6 prefix %s %s", id, c.IPv6.Prefix[id])
	}

	for _, name := range sortedKeys(c.Interface) {
		renderIface(r, name, c.Interface[name].Iface)
		r.opt("ngn type "+name, c.Interface[name].NgnType)
	}
	for _, id := range sortedKeys(c.Tunnel) {
		tunnel := c.Tunnel[id]
		r.context = "tunnel " + id
		r.opt("tunnel encapsulation", tunnel.Encapsulation)
		renderIface(r, "tunnel", tunnel.Iface)
		for _, raw := range tunnel.Raw {
			r.add("%s", raw)
		}
		if tunnel.Enable {
			r.add("tunnel enable %s", id)
		}
	}
	for _, id := range sortedKeys(c.PP) {
		pp := c.PP[id]
		r.context = "pp " + id
		renderIface(r, "pp", pp.Iface)
		for _, raw := range pp.Raw {
			r.add("%s", raw)
		}
		if pp.Enable {
			r.add("pp enable %s", id)
		}
	}
	r.context = ""

	for _, id := range sortedKeys(c.NAT) {
		r.opt("nat descriptor type "+id, c.NAT[id].Type)
		r.opt("nat descriptor address outer "+id, c.NAT[id].AddressOuter)
	}

	r.opt("telnetd service", c.Telnetd.Service)
	r.opt("telnetd host", c.Telnetd.Host)

	r.opt("dhcp service", c.DHCP.Service)
	r.opt("dhcp server rfc2131 compliant", c.DHCP.RFC2131Compliant)
	for _, id := range sortedKeys(c.DHCP.Scope) {
		scope := c.DHCP.Scope[id]
		r.opt("dhcp scope "+id, scope.Range)
		for _, bind := range scope.Binds {
			r.add("dhcp scope bind %s %s ethernet %s", id, bind.IP, bind.MAC)
		}
		r.opt("dhcp scope option "+id, scope.Options)
	}

	r.opt("dns host", c.DNS.Host)
	r.opt("dns service fallback", c.DNS.ServiceFallback)
	r.opt("dns server dhcp", c.DNS.ServerDHCP)
	for _, id := range sortedKeys(c.DNS.ServerSelect) {
		r.add("dns server select %s %s", id, c.DNS.ServerSelect[id])
	}
	r.opt("dns private address spoof", c.DNS.PrivateAddressSpoof)
	for _, record := range c.DNS.Static {
		text := fmt.Sprintf("dns static %s %s %s", record.Type, record.Name, record.Value)
		if record.TTL != 0 {
			text += " ttl=" + strconv.Itoa(record.TTL)
		}
		r.add("%s", text)
	}

	r.opt("httpd service", c.Httpd.Service)
	r.opt("httpd host", c.Httpd.Host)
	r.opt("sshd service", c.Sshd.Service)
	r.opt("sshd host", c.Sshd.Host)
	for _, kind := range sortedKeys(c.System.Statistics) {
		r.add("statistics %s %s", kind, c.System.Statistics[kind])
	}

	for _, raw := range c.Raw.Commands {
		r.add("%s", raw)
	}
	return r.lines
}

func renderUserAttribute(name string, attr UserAttribute) string {
	parts := []string{"user attribute"}
	if name != AnonymousUser {
		parts = append(parts, name)
	}
	add := func(key, value string) {
		if value != "" {
			parts = append(parts, key+"="+value)
		}
	}
	add("administrator", attr.Administrator)
	add("connection", strings.Join(attr.Connection, ","))
	add("gui-page", strings.Join(attr.GUIPage, ","))
	add("host", attr.Host)
	add("multi-session", attr.MultiSession)
	if attr.LoginTimer != 0 {
		add("login-timer", strconv.Itoa(attr.LoginTimer))
	}
	return strings.Join(parts, " ")
}

func renderFamily(r *renderer, family string, f IPFamily) {
	for _, id := range sortedKeys(f.Filter) {
		r.add("%s filter %s %s", family, id, renderFilter(f.Filter[id]))
	}
	for _, id := range sortedKeys(f.FilterDynamic) {
		r.add("%s filter dynamic %s %s", family, id, renderDynamicFilter(f.FilterDynamic[id]))
	}
	for _, network := range sortedKeys(f.Route) {
		r.add("%s route %s %s", family, network, f.Route[network])
	}
}

func orWildcard(value string) string {
	if value == "" {
		return "*"
	}
	return value
}

// renderFilter returns a filter definition without trailing *. src is required, so it is always written.
func renderFilter(f Filter) string {
	fields := []string{f.Action, orWildcard(f.Src), orWildcard(f.Dst), orWildcard(f.Proto), orWildcard(f.SrcPort), orWildcard(f.DstPort)}
	for len(fields) > 2 && fields[len(fields)-1] == "*" {
		fields = fields[:len(fields)-1]
	}
	return strings.Join(fields, " ")
}

func renderDynamicFilter(f DynamicFilter) string {
	text := fmt.Sprintf("%s %s %s", orWildcard(f.Src), orWildcard(f.Dst), f.Proto)
	if f.Options != "" {
		text += " " + f.Options
	}
	return text
}

func renderIface(r *renderer, name string, i Iface) {
	r.opt("description "+name, i.Description)
	r.opt("ip "+name+" address", i.IPAddress)
	for _, address := range i.IPv6Address {
		r.add("ipv6 %s address %s", name, address)
	}
	r.opt("ipv6 "+name+" rtadv send", i.IPv6RtadvSend)
	if i.IPMTU != 0 {
		r.add("ip %s mtu %d", name, i.IPMTU)
	}
	renderSecureFilter(r, "ip "+name, i.IPSecureFilter)
	renderSecureFilter(r, "ipv6 "+name, i.IPv6SecureFilter)
	r.opt("ip "+name+" nat descriptor", i.IPNATDescriptor)
	r.opt("ipv6 "+name+" dhcp service", i.IPv6DHCPService)
}

func renderSecureFilter(r *renderer, prefix string, f *SecureFilter) {
	if f.empty() {
		return
	}
	direction := func(name string, ids, dynamic []int) {
		if len(ids)+len(dynamic) == 0 {
			return
		}
		text := prefix + " secure filter " + name
		if len(ids) > 0 {
			text += " " + joinInts(ids)
		}
		if len(dynamic) > 0 {
			text += " dynamic " + joinInts(dynamic)
		}
		r.add("%s", text)
	}
	direction("in", f.In, f.InDynamic)
	direction("out", f.Out, f.OutDynamic)
}

func joinInts(values []int) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = strconv.Itoa(value)
	}
	return strings.Join(parts, " ")
}
