package plan

import (
	"slices"
	"strings"
	"testing"

	"github.com/eggplants/yamartx/internal/rtx"
)

func TestDiffNoChangesIgnoresProtectedAndWildcards(t *testing.T) {
	current := []rtx.Line{
		{Text: "login user operator *"},
		{Text: "ip filter 1 reject 10.0.0.0/8 * * * *"},
		{Context: "tunnel 1", Text: "tunnel enable 1"},
	}
	desired := []rtx.Line{
		{Text: "ip filter 1 reject 10.0.0.0/8"},
		{Context: "tunnel 1", Text: "tunnel enable 1"},
	}
	p, err := Diff(current, desired)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Empty() {
		t.Fatalf("expected no changes, got %+v", p.Items)
	}
	if len(p.Protected) != 1 {
		t.Errorf("protected = %v", p.Protected)
	}
}

func TestDiffRejectsProtectedAndConflicts(t *testing.T) {
	if _, err := Diff(nil, []rtx.Line{{Text: "login user a b"}}); err == nil {
		t.Error("protected line in desired must fail")
	}
	_, err := Diff(nil, []rtx.Line{{Text: "ip lan1 address 192.0.2.1/24"}, {Text: "ip lan1 address 192.0.2.2/24"}})
	if err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Errorf("conflict must fail, got %v", err)
	}
}

func TestCommandsOrderAndContexts(t *testing.T) {
	current := []rtx.Line{
		{Text: "ip route 10.0.0.0/8 gateway tunnel 1"},
		{Text: "ip filter 9 pass *"},
		{Text: "ipv6 lan2 secure filter in 9"},
		{Text: "ipv6 lan1 address fe80::1/64"},
		{Context: "tunnel 1", Text: "tunnel encapsulation map-e"},
		{Context: "tunnel 1", Text: "ip tunnel mtu 1460"},
		{Context: "tunnel 1", Text: "tunnel enable 1"},
		{Context: "pp 2", Text: "pp enable 2"},
		{Text: "dhcp scope 1 192.168.100.2-192.168.100.9/24"},
		{Text: "dhcp scope bind 1 192.168.100.2 ethernet 02:00:00:00:00:01"},
	}
	desired := []rtx.Line{
		{Text: "ipv6 lan2 secure filter in 1"}, // Reference changes come after new definitions
		{Text: "ipv6 filter 1 pass *"},
		{Context: "tunnel 3", Text: "tunnel enable 3"},
		{Context: "tunnel 3", Text: "tunnel encapsulation ipip"},
		{Text: "ipv6 lan1 address fe80::1/64"},
	}
	p, err := Diff(current, desired)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ipv6 filter 1 pass *",
		"ipv6 lan2 secure filter in 1",
		"tunnel select 3",
		"tunnel encapsulation ipip",
		"tunnel enable 3",
		"tunnel select none",
		// Removals start here, in reverse order: routes come first and scopes come after binds.
		"no ip route 10.0.0.0/8",
		"pp select 2",
		"no pp enable 2",
		"pp select none",
		"tunnel select 1",
		"no tunnel enable 1",
		"no ip tunnel mtu",
		"no tunnel encapsulation",
		"tunnel select none",
		"no dhcp scope bind 1 192.168.100.2",
		"no dhcp scope 1",
		"no ip filter 9",
	}
	if got := p.Commands(); !slices.Equal(got, want) {
		t.Fatalf("commands:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestChangeReissuesWithoutNo(t *testing.T) {
	p, err := Diff(
		[]rtx.Line{{Text: "ip filter 1 pass *"}},
		[]rtx.Line{{Text: "ip filter 1 reject *"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Commands(); !slices.Equal(got, []string{"ip filter 1 reject *"}) {
		t.Fatalf("commands = %q", got)
	}
	var out strings.Builder
	p.Write(&out, false)
	if !strings.Contains(out.String(), "~ ip filter 1 pass *") || !strings.Contains(out.String(), "=> ip filter 1 reject *") {
		t.Errorf("output = %q", out.String())
	}
	if got := p.Summary(); got != "Plan: 0 to add, 1 to change, 0 to remove." {
		t.Errorf("summary = %q", got)
	}
}

func TestLockoutRisks(t *testing.T) {
	p, err := Diff(
		[]rtx.Line{{Text: "sshd host lan1"}, {Text: "dns host lan1"}},
		[]rtx.Line{{Text: "ip lan1 address 192.0.2.1/24"}, {Text: "ipv6 lan1 secure filter in 1"}, {Text: "dns host lan2"}, {Text: "ip filter 1 pass *"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(p.LockoutRisks()); got != 3 {
		t.Fatalf("risks = %+v", p.LockoutRisks())
	}
}
