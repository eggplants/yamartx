// Package config handles the yamartx TOML configuration file.
//
// It converts between TOML and router command lines. Diffs are computed on command lines,
// so this package only translates between the readable form and those lines.
package config

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config represents a whole configuration file.
type Config struct {
	Connection    Connection               `toml:"connection"`
	System        System                   `toml:"system"`
	UserAttribute map[string]UserAttribute `toml:"user_attribute"`
	Sshd          Service                  `toml:"sshd"`
	Telnetd       Service                  `toml:"telnetd"`
	Httpd         Service                  `toml:"httpd"`
	Interface     map[string]LANInterface  `toml:"interface"`
	Tunnel        map[string]Tunnel        `toml:"tunnel"`
	PP            map[string]PP            `toml:"pp"`
	IP            IPFamily                 `toml:"ip"`
	IPv6          IPv6Family               `toml:"ipv6"`
	NAT           map[string]NAT           `toml:"nat"`
	DHCP          DHCP                     `toml:"dhcp"`
	DNS           DNS                      `toml:"dns"`
	Raw           Raw                      `toml:"raw"`
}

// Connection holds how to reach the router. Passwords come from the environment or a prompt.
type Connection struct {
	Host         string `toml:"host"`
	Port         int    `toml:"port"`
	User         string `toml:"user"`
	IdentityFile string `toml:"identity_file"`
	KnownHosts   string `toml:"known_hosts"`
}

// System holds the console and statistics settings.
type System struct {
	ConsoleCharacter string            `toml:"console_character"`
	ConsoleLines     string            `toml:"console_lines"`
	ConsoleColumns   string            `toml:"console_columns"`
	Statistics       map[string]string `toml:"statistics"`
}

// AnonymousUser is the key for user attribute lines that omit the user name.
const AnonymousUser = "anonymous"

// UserAttribute corresponds to the user attribute command.
type UserAttribute struct {
	Administrator string   `toml:"administrator"`
	Connection    []string `toml:"connection"`
	GUIPage       []string `toml:"gui_page"`
	Host          string   `toml:"host"`
	MultiSession  string   `toml:"multi_session"`
	LoginTimer    int      `toml:"login_timer"`
}

// Service holds the items shared by sshd, telnetd and httpd.
type Service struct {
	Service string `toml:"service"`
	Host    string `toml:"host"`
}

// SecureFilter corresponds to the ip and ipv6 secure filter commands.
type SecureFilter struct {
	In         []int `toml:"in"`
	InDynamic  []int `toml:"in_dynamic"`
	Out        []int `toml:"out"`
	OutDynamic []int `toml:"out_dynamic"`
}

func (f *SecureFilter) empty() bool {
	return f == nil || len(f.In)+len(f.InDynamic)+len(f.Out)+len(f.OutDynamic) == 0
}

// Iface holds the interface settings shared by LAN, tunnel and pp.
type Iface struct {
	Description      string        `toml:"description"`
	IPAddress        string        `toml:"ip_address"`
	IPv6Address      []string      `toml:"ipv6_address"`
	IPv6RtadvSend    string        `toml:"ipv6_rtadv_send"`
	IPv6DHCPService  string        `toml:"ipv6_dhcp_service"`
	IPMTU            int           `toml:"ip_mtu"`
	IPNATDescriptor  string        `toml:"ip_nat_descriptor"`
	IPSecureFilter   *SecureFilter `toml:"ip_secure_filter"`
	IPv6SecureFilter *SecureFilter `toml:"ipv6_secure_filter"`
}

// LANInterface corresponds to [interface.lanN].
type LANInterface struct {
	NgnType string `toml:"ngn_type"`
	Iface
}

// Tunnel corresponds to the tunnel select N context.
type Tunnel struct {
	Encapsulation string `toml:"encapsulation"`
	Enable        bool   `toml:"enable"`
	Iface
	Raw []string `toml:"raw"`
}

// PP corresponds to the pp select N context.
type PP struct {
	Enable bool `toml:"enable"`
	Iface
	Raw []string `toml:"raw"`
}

// Filter corresponds to ip filter and ipv6 filter. Omitted fields mean *.
type Filter struct {
	Action  string `toml:"action"`
	Src     string `toml:"src"`
	Dst     string `toml:"dst"`
	Proto   string `toml:"proto"`
	SrcPort string `toml:"src_port"`
	DstPort string `toml:"dst_port"`
}

// DynamicFilter corresponds to ip filter dynamic and ipv6 filter dynamic.
type DynamicFilter struct {
	Src     string `toml:"src"`
	Dst     string `toml:"dst"`
	Proto   string `toml:"proto"`
	Options string `toml:"options"`
}

// IPFamily holds the routes and filters shared by IPv4 and IPv6.
type IPFamily struct {
	Route         map[string]string        `toml:"route"`
	Filter        map[string]Filter        `toml:"filter"`
	FilterDynamic map[string]DynamicFilter `toml:"filter_dynamic"`
}

// IPv6Family is IPFamily plus the IPv6-specific items.
type IPv6Family struct {
	IPFamily
	Prefix map[string]string `toml:"prefix"`
}

// NAT corresponds to the nat descriptor commands.
type NAT struct {
	Type         string `toml:"type"`
	AddressOuter string `toml:"address_outer"`
}

// DHCP holds the DHCP server settings.
type DHCP struct {
	Service          string           `toml:"service"`
	RFC2131Compliant string           `toml:"rfc2131_compliant"`
	Scope            map[string]Scope `toml:"scope"`
}

// Scope is a dhcp scope with its bind and option entries.
type Scope struct {
	Range   string `toml:"range"`
	Options string `toml:"options"`
	Binds   []Bind `toml:"binds"`
}

// Bind corresponds to dhcp scope bind with a MAC address.
type Bind struct {
	IP  string `toml:"ip"`
	MAC string `toml:"mac"`
}

// DNS holds the DNS recursive server settings.
type DNS struct {
	Host                string            `toml:"host"`
	ServiceFallback     string            `toml:"service_fallback"`
	ServerDHCP          string            `toml:"server_dhcp"`
	PrivateAddressSpoof string            `toml:"private_address_spoof"`
	ServerSelect        map[string]string `toml:"server_select"`
	Static              []StaticRecord    `toml:"static"`
}

// StaticRecord corresponds to dns static.
type StaticRecord struct {
	Type  string `toml:"type"`
	Name  string `toml:"name"`
	Value string `toml:"value"`
	TTL   int    `toml:"ttl"`
}

// Raw holds global commands the schema does not cover, written verbatim.
type Raw struct {
	Commands []string `toml:"commands"`
}

// Load reads and validates a TOML file. Unknown keys are treated as typos and rejected.
func Load(path string) (*Config, error) {
	var c Config
	meta, err := toml.DecodeFile(path, &c)
	if err != nil {
		return nil, err
	}
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, key := range undecoded {
			keys[i] = key.String()
		}
		return nil, fmt.Errorf("%s: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

var (
	numericRe = regexp.MustCompile(`^[0-9]+$`)
	ifaceRe   = regexp.MustCompile(`^(lan|wan|bridge|loopback|vlan)[0-9./]+$`)
	actionRe  = regexp.MustCompile(`^(pass|reject|restrict)(-log|-nolog)?$`)
)

// Validate checks required items, ID formats and the safety of the generated commands.
func (c *Config) Validate() error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	numericKeys := func(section string, keys []string) {
		for _, key := range keys {
			if !numericRe.MatchString(key) {
				fail("[%s.%s]: id must be a number", section, key)
			}
		}
	}
	checkFilters := func(section string, family IPFamily) {
		numericKeys(section+".filter", sortedKeys(family.Filter))
		numericKeys(section+".filter_dynamic", sortedKeys(family.FilterDynamic))
		for _, id := range sortedKeys(family.Filter) {
			if !actionRe.MatchString(family.Filter[id].Action) {
				fail("[%s.filter.%s]: invalid action %q", section, id, family.Filter[id].Action)
			}
		}
		for _, id := range sortedKeys(family.FilterDynamic) {
			if family.FilterDynamic[id].Proto == "" {
				fail("[%s.filter_dynamic.%s]: proto is required", section, id)
			}
		}
	}
	checkFilters("ip", c.IP)
	checkFilters("ipv6", c.IPv6.IPFamily)
	numericKeys("ipv6.prefix", sortedKeys(c.IPv6.Prefix))
	numericKeys("nat", sortedKeys(c.NAT))
	numericKeys("tunnel", sortedKeys(c.Tunnel))
	numericKeys("dhcp.scope", sortedKeys(c.DHCP.Scope))
	numericKeys("dns.server_select", sortedKeys(c.DNS.ServerSelect))

	for _, name := range sortedKeys(c.Interface) {
		if !ifaceRe.MatchString(name) {
			fail("[interface.%s]: unsupported interface name (use [tunnel.N] or [pp.N] for those)", name)
		}
	}
	for _, id := range sortedKeys(c.PP) {
		if !numericRe.MatchString(id) && id != "anonymous" {
			fail("[pp.%s]: id must be a number or anonymous", id)
		}
	}
	for _, id := range sortedKeys(c.DHCP.Scope) {
		scope := c.DHCP.Scope[id]
		if scope.Range == "" {
			fail("[dhcp.scope.%s]: range is required", id)
		}
		for _, bind := range scope.Binds {
			if bind.IP == "" || bind.MAC == "" {
				fail("[dhcp.scope.%s]: binds need both ip and mac", id)
			}
		}
	}
	for _, record := range c.DNS.Static {
		if record.Type == "" || record.Name == "" || record.Value == "" {
			fail("[dns]: static records need type, name and value (got name %q)", record.Name)
		}
	}
	for _, line := range c.Render() {
		switch {
		case strings.ContainsAny(line.Text, "\r\n"):
			fail("command must be a single line: %q", line.Text)
		case strings.HasPrefix(line.Text, "no "):
			fail("raw commands must not use the no form: %q (remove the setting from the file instead)", line.Text)
		case strings.HasPrefix(line.Text, "tunnel select") || strings.HasPrefix(line.Text, "pp select"):
			fail("use [tunnel.N] or [pp.N] instead of %q", line.Text)
		case line.Protected():
			fail("%q is read-only: passwords and host keys are masked by show config, so yamartx never manages them", line.Text)
		}
	}
	return errors.Join(errs...)
}

// sortedKeys returns map keys with numbers in numeric order, then the rest alphabetically.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, errA := strconv.Atoi(keys[i])
		b, errB := strconv.Atoi(keys[j])
		switch {
		case errA == nil && errB == nil:
			return a < b
		case errA == nil:
			return true
		case errB == nil:
			return false
		}
		return keys[i] < keys[j]
	})
	return keys
}
