package rtx

import (
	"os"
	"slices"
	"testing"
)

func TestParseShowConfigContexts(t *testing.T) {
	got := ParseShowConfig("# header\r\nip lan1 address 192.168.100.1/24\r\ntunnel select 1\r\n tunnel encapsulation map-e\r\n tunnel enable 1\r\nip filter 1 pass *\r\npp select anonymous\r\n pp enable anonymous\r\ntelnetd service off\r\n")
	want := []Line{
		{"", "ip lan1 address 192.168.100.1/24"},
		{"tunnel 1", "tunnel encapsulation map-e"},
		{"tunnel 1", "tunnel enable 1"},
		{"", "ip filter 1 pass *"},
		{"pp anonymous", "pp enable anonymous"},
		{"", "telnetd service off"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
}

func TestKeyAndNoForm(t *testing.T) {
	tests := []struct{ text, no string }{
		{"ip filter 400000 reject 10.0.0.0/8 * * * *", "no ip filter 400000"},
		{"ip filter dynamic 400080 * * ftp", "no ip filter dynamic 400080"},
		{"ipv6 filter 101003 pass * * 4", "no ipv6 filter 101003"},
		{"ipv6 filter dynamic 101099 * * udp", "no ipv6 filter dynamic 101099"},
		{"ip route default gateway tunnel 1", "no ip route default"},
		{"ipv6 prefix 1 ra-prefix@lan2::/64", "no ipv6 prefix 1"},
		{"ip lan1 address 192.168.100.1/24", "no ip lan1 address"},
		{"ipv6 lan1 address ra-prefix@lan2::1/64", "no ipv6 lan1 address ra-prefix@lan2::1/64"},
		{"ipv6 lan1 rtadv send 1 o_flag=off", "no ipv6 lan1 rtadv send"},
		{"description lan2 Smart Home", "no description lan2"},
		{"ipv6 lan2 secure filter in 101000 101001", "no ipv6 lan2 secure filter in"},
		{"ip tunnel secure filter out 1 dynamic 2", "no ip tunnel secure filter out"},
		{"ipv6 lan2 dhcp service client ir=on", "no ipv6 lan2 dhcp service"},
		{"ngn type lan2 ntt", "no ngn type lan2"},
		{"tunnel encapsulation map-e", "no tunnel encapsulation"},
		{"ip tunnel mtu 1460", "no ip tunnel mtu"},
		{"ip tunnel nat descriptor 20000", "no ip tunnel nat descriptor"},
		{"tunnel enable 1", "no tunnel enable 1"},
		{"nat descriptor type 20000 masquerade", "no nat descriptor type 20000"},
		{"nat descriptor address outer 20000 map-e", "no nat descriptor address outer 20000"},
		{"nat descriptor masquerade static 1 2 192.168.100.4 tcp 443", "no nat descriptor masquerade static 1 2"},
		{"telnetd service off", "no telnetd service"},
		{"dhcp service server", "no dhcp service"},
		{"dhcp server rfc2131 compliant except remain-silent", "no dhcp server rfc2131 compliant"},
		{"dhcp scope 1 192.168.100.2-192.168.100.191/24", "no dhcp scope 1"},
		{"dhcp scope bind 1 192.168.100.2 ethernet 02:00:00:00:00:01", "no dhcp scope bind 1 192.168.100.2"},
		{"dhcp scope option 1 dns=192.168.100.4", "no dhcp scope option 1"},
		{"dns host lan1", "no dns host"},
		{"dns service fallback on", "no dns service fallback"},
		{"dns server dhcp lan2", "no dns server dhcp"},
		{"dns server select 500000 dhcp lan2 any .", "no dns server select 500000"},
		{"dns server 8.8.8.8 8.8.4.4", "no dns server"},
		{"dns private address spoof on", "no dns private address spoof"},
		{"dns static a nas.home.arpa 192.168.100.17", "no dns static a nas.home.arpa 192.168.100.17"},
		{"sshd host lan1", "no sshd host"},
		{"statistics traffic on", "no statistics traffic"},
		{"console character ja.utf8", "no console character"},
		{"user attribute connection=ssh login-timer=300", "no user attribute"},
		{"user attribute operator connection=ssh", "no user attribute operator"},
		{"something unknown here", "no something unknown here"},
	}
	for _, tt := range tests {
		if got := (Line{Text: tt.text}).NoForm(); got != tt.no {
			t.Errorf("NoForm(%q) = %q, want %q", tt.text, got, tt.no)
		}
	}
}

func TestProtected(t *testing.T) {
	protected := []string{
		"login password *",
		"administrator password *",
		"login user operator *",
		"sshd host key generate *",
		"pp auth myname user *",
		"ipsec ike pre-shared-key 1 text *",
	}
	for _, text := range protected {
		if !(Line{Text: text}).Protected() {
			t.Errorf("%q should be protected", text)
		}
	}
	notProtected := []string{
		"ip filter 400099 pass * * * * *",
		"ipv6 filter 101099 pass * * * * *",
		"ip filter dynamic 400080 * * *",
		"login timer 300",
		"sshd service on",
		"sshd host lan1",
	}
	for _, text := range notProtected {
		if (Line{Text: text}).Protected() {
			t.Errorf("%q should not be protected", text)
		}
	}
}

func TestCanonicalFilterTrailingWildcards(t *testing.T) {
	tests := []struct{ a, b string }{
		{"ipv6 filter 1 pass * * 4", "ipv6 filter 1 pass * * 4 * *"},
		{"ip filter 2 reject 10.0.0.0/8", "ip filter 2 reject 10.0.0.0/8 * * * *"},
		{"ip filter 3 pass * * tcp * 80", "ip filter 3 pass * * tcp * 80"},
	}
	for _, tt := range tests {
		a, b := Line{Text: tt.a}.Canonical(), Line{Text: tt.b}.Canonical()
		if a != b {
			t.Errorf("Canonical(%q) = %q, Canonical(%q) = %q", tt.a, a, tt.b, b)
		}
	}
	if (Line{Text: "ip filter 1 pass * * tcp"}).Canonical() == (Line{Text: "ip filter 1 pass * * udp"}).Canonical() {
		t.Error("different protocols must not compare equal")
	}
	dynamic := "ip filter dynamic 400098 * * *"
	if got := (Line{Text: dynamic}).Canonical(); got != dynamic {
		t.Errorf("dynamic filter must not change, got %q", got)
	}
}

func TestFixtureKeysAreUnique(t *testing.T) {
	data, err := os.ReadFile("../../testdata/show-config.txt")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, l := range ParseShowConfig(string(data)) {
		id := l.Context + "|" + l.Key()
		if prev, dup := seen[id]; dup {
			t.Errorf("key collision %q: %q and %q", id, prev, l.Text)
		}
		seen[id] = l.Text
	}
}
