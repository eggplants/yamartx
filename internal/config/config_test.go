package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/eggplants/yamartx/internal/rtx"
)

func fixture(t *testing.T) []rtx.Line {
	t.Helper()
	data, err := os.ReadFile("../../testdata/show-config.txt")
	if err != nil {
		t.Fatal(err)
	}
	return rtx.ParseShowConfig(string(data))
}

func loadText(t *testing.T, text string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "router.toml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func identities(lines []rtx.Line) []string {
	ids := make([]string, 0, len(lines))
	for _, line := range lines {
		if !line.Protected() {
			ids = append(ids, identity(line))
		}
	}
	slices.Sort(ids)
	return ids
}

func TestImportEncodeLoadRoundTrip(t *testing.T) {
	lines := fixture(t)
	imported, err := FromLines(lines)
	if err != nil {
		t.Fatal(err)
	}
	if len(imported.Raw.Commands) != 0 {
		t.Errorf("fixture should be fully structured, raw = %q", imported.Raw.Commands)
	}
	imported.Connection = Connection{Host: "192.0.2.1", User: "operator"}

	loaded, err := loadText(t, string(Encode(imported)))
	if err != nil {
		t.Fatalf("%v\n%s", err, Encode(imported))
	}
	if got, want := identities(loaded.Render()), identities(lines); !slices.Equal(got, want) {
		t.Fatalf("round trip mismatch\ngot  %q\nwant %q", got, want)
	}
	if loaded.Connection.Host != "192.0.2.1" {
		t.Errorf("connection lost: %+v", loaded.Connection)
	}
}

func TestExampleMatchesFixture(t *testing.T) {
	loaded, err := Load("../../examples/router.toml")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := identities(loaded.Render()), identities(fixture(t)); !slices.Equal(got, want) {
		t.Fatalf("examples/router.toml is out of date\ngot  %q\nwant %q", got, want)
	}
}

func TestImportFallsBackToRaw(t *testing.T) {
	lines := []rtx.Line{
		{Text: "ip lan1 secure filter name lanset"},
		{Text: "ip filter dynamic 1 * * filter 2 in 3 out 4"},
		{Text: "user attribute foo login-timer=300 connection=ssh"},
		{Text: "user attribute anonymous connection=ssh"},
		{Text: "dhcp scope bind 1 192.168.100.9 ipcp"},
		{Text: "nat descriptor masquerade static 1 2 192.168.100.4 tcp 443"},
		{Text: "description 1 site description"},
		{Context: "tunnel 1", Text: "ipsec ike version 1 2"},
		{Context: "pp 1", Text: "pp bind pppoe"},
	}
	imported, err := FromLines(lines)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(imported.Raw.Commands); got != 7 {
		t.Errorf("global raw = %q", imported.Raw.Commands)
	}
	if got := imported.Tunnel["1"].Raw; len(got) != 1 {
		t.Errorf("tunnel raw = %q", got)
	}
	if got := imported.PP["1"].Raw; len(got) != 1 {
		t.Errorf("pp raw = %q", got)
	}
	loaded, err := loadText(t, string(Encode(imported)))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := identities(loaded.Render()), identities(lines); !slices.Equal(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestImportKeepsSpacesInDescriptionAndSkipsProtected(t *testing.T) {
	imported, err := FromLines([]rtx.Line{
		{Text: "description lan1 Home  LAN"},
		{Text: "login user operator *"},
		{Text: "sshd host key generate *"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := imported.Interface["lan1"].Description; got != "Home  LAN" {
		t.Errorf("description = %q", got)
	}
	encoded := string(Encode(imported))
	if strings.Contains(encoded, "login user") || strings.Contains(encoded, "key generate") {
		t.Errorf("protected line leaked into TOML:\n%s", encoded)
	}
}

func TestEncodeEscapesStrings(t *testing.T) {
	loaded, err := loadText(t, string(Encode(&Config{
		Interface: map[string]LANInterface{"lan1": {Iface: Iface{Description: `a "quoted" \ value`}}},
	})))
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Interface["lan1"].Description; got != `a "quoted" \ value` {
		t.Errorf("description = %q", got)
	}
}

func TestLoadRejectsBadInput(t *testing.T) {
	tests := []struct{ name, text, want string }{
		{"unknown key", "[sshd]\nservise = \"on\"\n", "unknown keys"},
		{"bad action", "[ip.filter]\n1 = { action = \"allow\" }\n", "invalid action"},
		{"bad filter id", "[ip.filter]\nabc = { action = \"pass\" }\n", "must be a number"},
		{"dynamic without proto", "[ip.filter_dynamic]\n1 = { src = \"*\" }\n", "proto is required"},
		{"scope without range", "[dhcp.scope.1]\noptions = \"dns=1.1.1.1\"\n", "range is required"},
		{"tunnel as interface", "[interface.tunnel]\ndescription = \"x\"\n", "unsupported interface"},
		{"ngn on tunnel", "[tunnel.1]\nngn_type = \"ntt\"\n", "unknown keys"},
		{"masked password", "[raw]\ncommands = [\"login user foo *\"]\n", "read-only"},
		{"host key", "[raw]\ncommands = [\"sshd host key generate\"]\n", "read-only"},
		{"interactive password", "[raw]\ncommands = [\"administrator password\"]\n", "read-only"},
		{"no form", "[raw]\ncommands = [\"no ip filter 1\"]\n", "no form"},
		{"context in raw", "[raw]\ncommands = [\"tunnel select 1\"]\n", "instead of"},
		{"newline injection", "[raw]\ncommands = [\"dns host lan1\\nsave\"]\n", "single line"},
		{"newline in value", "[interface.lan1]\ndescription = \"x\\nsave\"\n", "single line"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadText(t, tt.text)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}
