package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/eggplants/yamartx/internal/fakertx"
	"github.com/eggplants/yamartx/internal/rtx"
	"github.com/eggplants/yamartx/internal/session"
)

func TestMain(m *testing.M) {
	session.QuietPeriod = 10 * time.Millisecond
	os.Exit(m.Run())
}

const smallConfig = `# RTX830 Rev.15.02.33
login user operator *
sshd host key generate *
console character ja.utf8
ip lan1 address 192.168.100.1/24
tunnel select 1
 tunnel encapsulation map-e
 ip tunnel mtu 1460
 tunnel enable 1
ip filter 1 pass * * * * *
ip filter 2 reject 10.0.0.0/8 * * * *
dns static a old.home.arpa 192.168.100.9
`

type result struct {
	code           int
	err            error
	stdout, stderr string
}

func exec(stdin string, args ...string) result {
	var stdout, stderr bytes.Buffer
	code, err := run(args, strings.NewReader(stdin), &stdout, &stderr)
	return result{code, err, stdout.String(), stderr.String()}
}

func startRouter(t *testing.T, showConfig string) *fakertx.Server {
	t.Helper()
	t.Setenv("YAMARTX_PASSWORD", fakertx.Password)
	t.Setenv("YAMARTX_ADMIN_PASSWORD", fakertx.AdminPassword)
	return fakertx.Start(t, showConfig)
}

func connArgs(s *fakertx.Server) []string {
	return []string{"-host", s.Host, "-port", strconv.Itoa(s.Port), "-user", fakertx.User, "-known-hosts", s.KnownHosts}
}

// importConfig imports TOML from the router and returns its path.
func importConfig(t *testing.T, s *fakertx.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "router.toml")
	args := append([]string{"import", "-o", path}, connArgs(s)...)
	if r := exec("", args...); r.err != nil || r.code != 0 {
		t.Fatalf("import: %+v", r)
	}
	return path
}

func rewrite(t *testing.T, path, old, replacement string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), old) {
		t.Fatalf("%q not found in:\n%s", old, data)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(data), old, replacement, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func hasLine(lines []rtx.Line, context, text string) bool {
	return slices.Contains(lines, rtx.Line{Context: context, Text: text})
}

func TestImportThenPlanHasNoChanges(t *testing.T) {
	s := startRouter(t, smallConfig)
	path := importConfig(t, s)

	r := exec("", "plan", "-c", path, "-detailed-exitcode")
	if r.err != nil || r.code != 0 {
		t.Fatalf("plan: %+v", r)
	}
	if !strings.Contains(r.stdout, "No changes.") || !strings.Contains(r.stdout, "2 protected lines ignored") {
		t.Errorf("stdout = %q", r.stdout)
	}
	// Reading restores the console settings and does not save.
	if hasLine(s.Lines(), "", "console lines infinity") {
		t.Error("console lines left modified")
	}
	if slices.Contains(s.Commands(), "save") {
		t.Error("plan must not save")
	}
}

func TestPlanDoesNotChangeRouter(t *testing.T) {
	s := startRouter(t, smallConfig)
	path := importConfig(t, s)
	rewrite(t, path, "ip_mtu = 1460", "ip_mtu = 1400")
	before := s.Lines()

	r := exec("", "plan", "-c", path, "-detailed-exitcode", "-commands")
	if r.err != nil || r.code != exitChanges {
		t.Fatalf("plan: %+v", r)
	}
	for _, want := range []string{"~ [tunnel 1] ip tunnel mtu 1460", "=> ip tunnel mtu 1400", "Plan: 0 to add, 1 to change, 0 to remove.", "tunnel select 1"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("missing %q in:\n%s", want, r.stdout)
		}
	}
	if !slices.Equal(s.Lines(), before) {
		t.Errorf("plan changed the router:\n%v\n%v", s.Lines(), before)
	}
}

func TestApplyChangesAndSaves(t *testing.T) {
	s := startRouter(t, smallConfig)
	path := importConfig(t, s)
	rewrite(t, path, "ip_mtu = 1460", "ip_mtu = 1400")
	rewrite(t, path, `{ type = "a", name = "old.home.arpa", value = "192.168.100.9" },`, `{ type = "a", name = "new.home.arpa", value = "192.168.100.10" },`)

	r := exec("yes\n", "apply", "-c", path)
	if r.err != nil || r.code != 0 {
		t.Fatalf("apply: %+v", r)
	}
	if !strings.Contains(r.stdout, "Apply complete.") {
		t.Errorf("stdout = %s", r.stdout)
	}
	for _, lines := range [][]rtx.Line{s.Lines(), s.Saved()} {
		if !hasLine(lines, "tunnel 1", "ip tunnel mtu 1400") || !hasLine(lines, "", "dns static a new.home.arpa 192.168.100.10") {
			t.Errorf("not applied: %v", lines)
		}
		if hasLine(lines, "", "dns static a old.home.arpa 192.168.100.9") {
			t.Errorf("old record remains: %v", lines)
		}
		// Passwords and temporary console settings do not affect the saved configuration.
		if !hasLine(lines, "", "login user operator *") || !hasLine(lines, "", "sshd host key generate *") {
			t.Errorf("protected line touched: %v", lines)
		}
		if slices.ContainsFunc(lines, func(l rtx.Line) bool {
			return strings.HasPrefix(l.Text, "console lines") || strings.HasPrefix(l.Text, "console columns")
		}) {
			t.Errorf("temporary console settings persisted: %v", lines)
		}
	}
	// The second run has no changes.
	if r := exec("", "apply", "-c", path, "-auto-approve"); r.err != nil || !strings.Contains(r.stdout, "No changes.") {
		t.Errorf("second apply: %+v", r)
	}
}

func TestApplyRestoresExistingConsoleSettings(t *testing.T) {
	s := startRouter(t, smallConfig+"console lines 50\nconsole columns 120\n")
	path := importConfig(t, s)
	r := exec("", "plan", "-c", path)
	if r.err != nil || !strings.Contains(r.stdout, "No changes.") {
		t.Fatalf("plan: %+v", r)
	}
	lines := s.Lines()
	if !hasLine(lines, "", "console lines 50") || !hasLine(lines, "", "console columns 120") {
		t.Errorf("console settings not restored: %v", lines)
	}
}

func TestApplyDeclined(t *testing.T) {
	s := startRouter(t, smallConfig)
	path := importConfig(t, s)
	rewrite(t, path, "ip_mtu = 1460", "ip_mtu = 1400")

	r := exec("no\n", "apply", "-c", path)
	if r.code != 1 || !strings.Contains(r.stdout, "Apply cancelled.") {
		t.Fatalf("apply: %+v", r)
	}
	if !hasLine(s.Lines(), "tunnel 1", "ip tunnel mtu 1460") {
		t.Error("router changed despite declining")
	}
}

func TestApplyStopsOnErrorWithoutSaving(t *testing.T) {
	s := startRouter(t, smallConfig)
	path := importConfig(t, s)
	rewrite(t, path, `{ type = "a", name = "old.home.arpa", value = "192.168.100.9" },`,
		`{ type = "a", name = "old.home.arpa", value = "192.168.100.9" },
  { type = "a", name = "first.home.arpa", value = "192.168.100.20" },
  { type = "a", name = "bad.home.arpa", value = "192.168.100.21" },
  { type = "a", name = "third.home.arpa", value = "192.168.100.22" },`)
	s.FailOn = "bad.home.arpa"

	r := exec("yes\n", "apply", "-c", path)
	if r.code != 1 || r.err == nil || !strings.Contains(r.err.Error(), "Nothing was saved") {
		t.Fatalf("apply: %+v", r)
	}
	if slices.Contains(s.Commands(), "save") {
		t.Error("save must not run after a failure")
	}
	if hasLine(s.Lines(), "", "dns static a third.home.arpa 192.168.100.22") {
		t.Error("commands after the failure must not run")
	}
	if hasLine(s.Saved(), "", "dns static a first.home.arpa 192.168.100.20") {
		t.Error("partial changes must not be saved")
	}
}

func TestApplyLosesConnectionWithoutSaving(t *testing.T) {
	s := startRouter(t, smallConfig)
	path := importConfig(t, s)
	rewrite(t, path, "ip_mtu = 1460", "ip_mtu = 1400")
	s.DropOn = "ip tunnel mtu 1400"

	r := exec("yes\n", "apply", "-c", path)
	if r.code != 1 || r.err == nil || !strings.Contains(r.err.Error(), "connection closed") {
		t.Fatalf("apply: %+v", r)
	}
	if slices.Contains(s.Commands(), "save") {
		t.Error("save must not run after losing the connection")
	}
}

func TestApplyDeclinesConfirmationPrompts(t *testing.T) {
	s := startRouter(t, smallConfig)
	path := importConfig(t, s)
	rewrite(t, path, "ip_mtu = 1460", "ip_mtu = 1400")
	s.ConfirmOn = "ip tunnel mtu"

	r := exec("yes\n", "apply", "-c", path)
	if r.code != 1 || r.err == nil || !strings.Contains(r.err.Error(), "asked for confirmation") {
		t.Fatalf("apply: %+v", r)
	}
}

func TestAutoApproveRefusesLockoutRisk(t *testing.T) {
	s := startRouter(t, smallConfig+"sshd service on\nsshd host lan1\n")
	path := importConfig(t, s)
	rewrite(t, path, `host = "lan1"`, `host = "lan2"`)

	r := exec("", "apply", "-c", path, "-auto-approve")
	if r.code != 1 || r.err == nil || !strings.Contains(r.err.Error(), "allow-lockout-risk") {
		t.Fatalf("apply: %+v", r)
	}
	if !strings.Contains(r.stdout, "could cut off remote access") {
		t.Errorf("stdout = %s", r.stdout)
	}
	if !hasLine(s.Lines(), "", "sshd host lan1") {
		t.Error("router changed")
	}
	if r := exec("", "apply", "-c", path, "-auto-approve", "-allow-lockout-risk"); r.err != nil {
		t.Fatalf("apply: %+v", r)
	}
	if !hasLine(s.Saved(), "", "sshd host lan2") {
		t.Error("not applied with explicit permission")
	}
}

func TestApplyNoSave(t *testing.T) {
	s := startRouter(t, smallConfig)
	path := importConfig(t, s)
	rewrite(t, path, "ip_mtu = 1460", "ip_mtu = 1400")

	if r := exec("", "apply", "-c", path, "-auto-approve", "-no-save"); r.err != nil {
		t.Fatalf("apply: %+v", r)
	}
	if !hasLine(s.Lines(), "tunnel 1", "ip tunnel mtu 1400") || hasLine(s.Saved(), "tunnel 1", "ip tunnel mtu 1400") {
		t.Errorf("running %v\nsaved %v", s.Lines(), s.Saved())
	}
}

func TestApplyReportsResidualDifferences(t *testing.T) {
	s := startRouter(t, smallConfig)
	path := importConfig(t, s)
	rewrite(t, path, "ip_mtu = 1460", "ip_mtu = 1400")
	// Reproduce a router displaying input in a different form.
	s.Rewrite = func(command string) string {
		return strings.Replace(command, "ip tunnel mtu 1400", "ip tunnel mtu 1401", 1)
	}
	r := exec("", "apply", "-c", path, "-auto-approve")
	if r.code != 1 || r.err == nil || !strings.Contains(r.err.Error(), "1 differences remain") {
		t.Fatalf("apply: %+v", r)
	}
}

func TestConnectionFailures(t *testing.T) {
	s := startRouter(t, smallConfig)
	path := importConfig(t, s)

	t.Run("wrong admin password", func(t *testing.T) {
		t.Setenv("YAMARTX_ADMIN_PASSWORD", "wrong")
		r := exec("", "plan", "-c", path)
		if r.err == nil || !strings.Contains(r.err.Error(), "authentication failed") {
			t.Fatalf("plan: %+v", r)
		}
	})
	t.Run("wrong login password", func(t *testing.T) {
		t.Setenv("YAMARTX_PASSWORD", "wrong")
		if r := exec("", "plan", "-c", path); r.err == nil {
			t.Fatalf("plan: %+v", r)
		}
	})
	t.Run("unknown host key", func(t *testing.T) {
		empty := filepath.Join(t.TempDir(), "known_hosts")
		if err := os.WriteFile(empty, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		r := exec("", "plan", "-c", path, "-known-hosts", empty)
		if r.err == nil || !strings.Contains(r.err.Error(), "is not in") {
			t.Fatalf("plan: %+v", r)
		}
	})
	t.Run("no password without a terminal", func(t *testing.T) {
		t.Setenv("YAMARTX_ADMIN_PASSWORD", "")
		os.Unsetenv("YAMARTX_ADMIN_PASSWORD")
		r := exec("", "plan", "-c", path)
		if r.err == nil || !strings.Contains(r.err.Error(), "YAMARTX_ADMIN_PASSWORD") {
			t.Fatalf("plan: %+v", r)
		}
	})
}

func TestColumnsFallback(t *testing.T) {
	s := startRouter(t, smallConfig)
	s.MaxColumns = 200
	path := importConfig(t, s)
	if r := exec("", "plan", "-c", path); r.err != nil || !strings.Contains(r.stdout, "No changes.") {
		t.Fatalf("plan: %+v", r)
	}
	if !slices.Contains(s.Commands(), "console columns 200") {
		t.Errorf("commands = %v", s.Commands())
	}
}

func TestShowConfigContainingErrorWordIsNotAFailure(t *testing.T) {
	s := startRouter(t, smallConfig+"description lan1 エラー: 監視用 Error: test\n")
	path := importConfig(t, s)
	if r := exec("", "plan", "-c", path); r.err != nil || !strings.Contains(r.stdout, "No changes.") {
		t.Fatalf("plan: %+v", r)
	}
}

func TestUnexpectedShowConfigOutputIsRejected(t *testing.T) {
	s := startRouter(t, smallConfig)
	path := importConfig(t, s)
	s.ShowConfigOutput = "Access denied\n"
	r := exec("yes\n", "apply", "-c", path)
	if r.err == nil || !strings.Contains(r.err.Error(), "unexpected show config output") {
		t.Fatalf("apply: %+v", r)
	}
	if !hasLine(s.Lines(), "", "ip lan1 address 192.168.100.1/24") {
		t.Error("router changed")
	}
	if hasLine(s.Lines(), "", "console lines infinity") {
		t.Error("console settings were not restored after the failure")
	}
}

func TestOfflineFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "router.toml")
	source := "../../testdata/show-config.txt"
	if r := exec("", "import", "-from-file", source, "-o", path); r.err != nil {
		t.Fatalf("import: %+v", r)
	}
	// Overwriting requires -force.
	if r := exec("", "import", "-from-file", source, "-o", path); r.err == nil || !strings.Contains(r.err.Error(), "-force") {
		t.Fatalf("second import: %+v", r)
	}
	r := exec("", "plan", "-c", path, "-from-file", source, "-detailed-exitcode")
	if r.err != nil || r.code != 0 || !strings.Contains(r.stdout, "No changes.") || !strings.Contains(r.stdout, "4 protected lines") {
		t.Fatalf("plan: %+v", r)
	}
	r = exec("", "render", "-c", path)
	if r.err != nil || !strings.Contains(r.stdout, "tunnel select 1\n tunnel encapsulation map-e\n") {
		t.Fatalf("render: %+v", r)
	}
}

func TestUsageAndErrors(t *testing.T) {
	if r := exec(""); r.code != 1 || !strings.Contains(r.stderr, "Usage") {
		t.Errorf("no args: %+v", r)
	}
	if r := exec("", "--help"); r.code != 0 || !strings.Contains(r.stdout, "Usage") {
		t.Errorf("help: %+v", r)
	}
	if r := exec("", "version"); r.code != 0 || !strings.HasPrefix(r.stdout, "yamartx ") {
		t.Errorf("version: %+v", r)
	}
	if r := exec("", "bogus"); r.code != 1 || r.err == nil {
		t.Errorf("unknown: %+v", r)
	}
	if r := exec("", "plan", "-h"); r.code != 0 {
		t.Errorf("plan -h: %+v", r)
	}
	if r := exec("", "plan", "stray"); r.code != 1 || r.err == nil {
		t.Errorf("stray arg: %+v", r)
	}
	if r := exec("", "import"); r.code != 1 || r.err == nil || !strings.Contains(r.err.Error(), "host and user") {
		t.Errorf("import without host: %+v", r)
	}
}
