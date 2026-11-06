package config

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Encode converts the configuration into TOML with a readable layout.
//
// A generic encoder would give each filter its own table and make the file very long,
// so the output is built by hand to keep each filter on one line as an inline table.
func Encode(c *Config) []byte {
	var w tomlWriter
	w.b.WriteString("# yamartx configuration. Anything the router has but this file lacks is removed on apply.\n")
	w.b.WriteString("# Passwords and SSH host keys are never managed: show config masks them.\n")

	w.table("connection",
		str("host", c.Connection.Host),
		integer("port", c.Connection.Port),
		str("user", c.Connection.User),
		str("identity_file", c.Connection.IdentityFile),
		str("known_hosts", c.Connection.KnownHosts),
	)
	w.table("system",
		str("console_character", c.System.ConsoleCharacter),
		str("console_lines", c.System.ConsoleLines),
		str("console_columns", c.System.ConsoleColumns),
	)
	w.table("system.statistics", stringMap(c.System.Statistics)...)
	for _, name := range sortedKeys(c.UserAttribute) {
		attr := c.UserAttribute[name]
		w.table("user_attribute."+key(name),
			str("administrator", attr.Administrator),
			strs("connection", attr.Connection),
			strs("gui_page", attr.GUIPage),
			str("host", attr.Host),
			str("multi_session", attr.MultiSession),
			integer("login_timer", attr.LoginTimer),
		)
	}
	w.table("sshd", str("service", c.Sshd.Service), str("host", c.Sshd.Host))
	w.table("telnetd", str("service", c.Telnetd.Service), str("host", c.Telnetd.Host))
	w.table("httpd", str("service", c.Httpd.Service), str("host", c.Httpd.Host))

	for _, name := range sortedKeys(c.Interface) {
		w.iface("interface."+key(name), []string{str("ngn_type", c.Interface[name].NgnType)}, c.Interface[name].Iface, nil)
	}
	for _, id := range sortedKeys(c.Tunnel) {
		tunnel := c.Tunnel[id]
		w.iface("tunnel."+key(id), []string{str("encapsulation", tunnel.Encapsulation), boolean("enable", tunnel.Enable)}, tunnel.Iface, tunnel.Raw)
	}
	for _, id := range sortedKeys(c.PP) {
		pp := c.PP[id]
		w.iface("pp."+key(id), []string{boolean("enable", pp.Enable)}, pp.Iface, pp.Raw)
	}

	w.family("ip", c.IP)
	w.family("ipv6", c.IPv6.IPFamily)
	w.table("ipv6.prefix", stringMap(c.IPv6.Prefix)...)

	for _, id := range sortedKeys(c.NAT) {
		w.table("nat."+key(id), str("type", c.NAT[id].Type), str("address_outer", c.NAT[id].AddressOuter))
	}

	w.table("dhcp", str("service", c.DHCP.Service), str("rfc2131_compliant", c.DHCP.RFC2131Compliant))
	for _, id := range sortedKeys(c.DHCP.Scope) {
		scope := c.DHCP.Scope[id]
		binds := make([]string, len(scope.Binds))
		for i, bind := range scope.Binds {
			binds[i] = inline(str("ip", bind.IP), str("mac", bind.MAC))
		}
		w.table("dhcp.scope."+key(id),
			str("range", scope.Range),
			str("options", scope.Options),
			multiline("binds", binds),
		)
	}

	records := make([]string, len(c.DNS.Static))
	for i, record := range c.DNS.Static {
		records[i] = inline(str("type", record.Type), str("name", record.Name), str("value", record.Value), integer("ttl", record.TTL))
	}
	w.table("dns",
		str("host", c.DNS.Host),
		str("service_fallback", c.DNS.ServiceFallback),
		str("server_dhcp", c.DNS.ServerDHCP),
		str("private_address_spoof", c.DNS.PrivateAddressSpoof),
		multiline("static", records),
	)
	w.table("dns.server_select", stringMap(c.DNS.ServerSelect)...)

	w.table("raw", multiline("commands", quoteAll(c.Raw.Commands)))
	return []byte(w.b.String())
}

type tomlWriter struct{ b strings.Builder }

// table writes a table only if at least one entry is non-empty.
func (w *tomlWriter) table(name string, entries ...string) {
	present := entries[:0:0]
	for _, entry := range entries {
		if entry != "" {
			present = append(present, entry)
		}
	}
	if len(present) == 0 {
		return
	}
	fmt.Fprintf(&w.b, "\n[%s]\n", name)
	for _, entry := range present {
		w.b.WriteString(entry + "\n")
	}
}

func (w *tomlWriter) iface(name string, head []string, i Iface, raw []string) {
	entries := append(head,
		str("description", i.Description),
		str("ip_address", i.IPAddress),
		strs("ipv6_address", i.IPv6Address),
		str("ipv6_rtadv_send", i.IPv6RtadvSend),
		str("ipv6_dhcp_service", i.IPv6DHCPService),
		integer("ip_mtu", i.IPMTU),
		str("ip_nat_descriptor", i.IPNATDescriptor),
		multiline("raw", quoteAll(raw)),
	)
	w.table(name, entries...)
	w.secureFilter(name+".ip_secure_filter", i.IPSecureFilter)
	w.secureFilter(name+".ipv6_secure_filter", i.IPv6SecureFilter)
}

func (w *tomlWriter) secureFilter(name string, f *SecureFilter) {
	if f.empty() {
		return
	}
	w.table(name,
		ints("in", f.In),
		ints("in_dynamic", f.InDynamic),
		ints("out", f.Out),
		ints("out_dynamic", f.OutDynamic),
	)
}

func (w *tomlWriter) family(name string, f IPFamily) {
	w.table(name+".route", stringMap(f.Route)...)

	filters := make([]string, 0, len(f.Filter))
	for _, id := range sortedKeys(f.Filter) {
		filter := f.Filter[id]
		filters = append(filters, key(id)+" = "+inline(
			str("action", filter.Action),
			str("src", filter.Src),
			str("dst", filter.Dst),
			str("proto", filter.Proto),
			str("src_port", filter.SrcPort),
			str("dst_port", filter.DstPort),
		))
	}
	w.table(name+".filter", filters...)

	dynamic := make([]string, 0, len(f.FilterDynamic))
	for _, id := range sortedKeys(f.FilterDynamic) {
		filter := f.FilterDynamic[id]
		dynamic = append(dynamic, key(id)+" = "+inline(
			str("src", filter.Src),
			str("dst", filter.Dst),
			str("proto", filter.Proto),
			str("options", filter.Options),
		))
	}
	w.table(name+".filter_dynamic", dynamic...)
}

var bareKeyRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func key(name string) string {
	if bareKeyRe.MatchString(name) {
		return name
	}
	return quote(name)
}

var quoteReplacer = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

func quote(value string) string {
	return `"` + quoteReplacer.Replace(value) + `"`
}

func quoteAll(values []string) []string {
	quoted := make([]string, len(values))
	for i, value := range values {
		quoted[i] = quote(value)
	}
	return quoted
}

func str(name, value string) string {
	if value == "" {
		return ""
	}
	return name + " = " + quote(value)
}

func integer(name string, value int) string {
	if value == 0 {
		return ""
	}
	return name + " = " + strconv.Itoa(value)
}

func boolean(name string, value bool) string {
	if !value {
		return ""
	}
	return name + " = true"
}

func strs(name string, values []string) string {
	if len(values) == 0 {
		return ""
	}
	return name + " = [" + strings.Join(quoteAll(values), ", ") + "]"
}

func ints(name string, values []int) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = strconv.Itoa(value)
	}
	return name + " = [" + strings.Join(parts, ", ") + "]"
}

func inline(entries ...string) string {
	present := entries[:0:0]
	for _, entry := range entries {
		if entry != "" {
			present = append(present, entry)
		}
	}
	return "{ " + strings.Join(present, ", ") + " }"
}

// multiline returns an array with one element per line.
func multiline(name string, items []string) string {
	if len(items) == 0 {
		return ""
	}
	return name + " = [\n  " + strings.Join(items, ",\n  ") + ",\n]"
}

func stringMap(m map[string]string) []string {
	entries := make([]string, 0, len(m))
	for _, name := range sortedKeys(m) {
		entries = append(entries, key(name)+" = "+quote(m[name]))
	}
	return entries
}
