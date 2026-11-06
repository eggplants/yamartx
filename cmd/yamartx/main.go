// Command yamartx declaratively manages Yamaha RTX configuration with TOML.
//
// It compares the router's show config with a local TOML file, then shows and applies the diff like terraform.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"golang.org/x/term"

	"github.com/eggplants/yamartx/internal/config"
	"github.com/eggplants/yamartx/internal/plan"
	"github.com/eggplants/yamartx/internal/rtx"
	"github.com/eggplants/yamartx/internal/session"
)

// version is set by GoReleaser via -ldflags "-X main.version=...".
var version = ""

const usage = `Usage: yamartx <command> [options]

Commands:
  import   Read the router's config and write it as TOML
  plan     Show what apply would change
  apply    Change the router to match the TOML file, then save
  render   Print the commands the TOML file describes (offline)
  version  Show version and exit

Run "yamartx <command> -h" for the options of a command.

Environment:
  YAMARTX_PASSWORD        Login password (prompted if unset)
  YAMARTX_ADMIN_PASSWORD  Administrator password (prompted if unset)
`

const defaultConfigPath = "router.toml"

func getVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

func main() {
	code, err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "yamartx:", err)
	}
	os.Exit(code)
}

// exitChanges is the exit code plan -detailed-exitcode uses when there are changes.
const exitChanges = 2

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 1, nil
	}
	a := &app{stdin: stdin, stdout: stdout, stderr: stderr}
	switch args[0] {
	case "import":
		return a.runImport(args[1:])
	case "plan":
		return a.runPlan(args[1:])
	case "apply":
		return a.runApply(args[1:])
	case "render":
		return a.runRender(args[1:])
	case "version", "-v", "--version":
		fmt.Fprintln(stdout, "yamartx", getVersion())
		return 0, nil
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0, nil
	}
	return 1, fmt.Errorf("unknown command %q (run yamartx --help)", args[0])
}

type app struct {
	stdin          io.Reader
	stdout, stderr io.Writer
}

// connFlags holds the flags that override the connection target.
type connFlags struct {
	host, user, identity, knownHosts string
	port                             int
}

func addConnFlags(fs *flag.FlagSet) *connFlags {
	c := &connFlags{}
	fs.StringVar(&c.host, "host", "", "router address (overrides [connection] host)")
	fs.IntVar(&c.port, "port", 0, "SSH port (overrides [connection] port)")
	fs.StringVar(&c.user, "user", "", "login user (overrides [connection] user)")
	fs.StringVar(&c.identity, "i", "", "SSH private key file (overrides [connection] identity_file)")
	fs.StringVar(&c.knownHosts, "known-hosts", "", "known_hosts file (default ~/.ssh/known_hosts)")
	return c
}

func (c *connFlags) merge(conn *config.Connection) {
	if c.host != "" {
		conn.Host = c.host
	}
	if c.port != 0 {
		conn.Port = c.port
	}
	if c.user != "" {
		conn.User = c.user
	}
	if c.identity != "" {
		conn.IdentityFile = c.identity
	}
	if c.knownHosts != "" {
		conn.KnownHosts = c.knownHosts
	}
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// parseFlags returns done so that -h can be treated as a normal exit.
func parseFlags(fs *flag.FlagSet, args []string) (done bool, code int, err error) {
	err = fs.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		return true, 0, nil
	}
	if err != nil {
		return true, 1, nil // The flag package has already printed the message
	}
	if fs.NArg() > 0 {
		return true, 1, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return false, 0, nil
}

func (a *app) runImport(args []string) (int, error) {
	fs := newFlagSet("import", a.stderr)
	conn := addConnFlags(fs)
	fromFile := fs.String("from-file", "", "read show config output from a file instead of the router")
	output := fs.String("o", "-", "output file (- for stdout)")
	force := fs.Bool("force", false, "overwrite the output file if it exists")
	if done, code, err := parseFlags(fs, args); done {
		return code, err
	}

	var connection config.Connection
	conn.merge(&connection)

	var lines []rtx.Line
	var err error
	if *fromFile != "" {
		lines, err = readShowConfigFile(*fromFile)
	} else {
		lines, err = a.readRouter(connection)
	}
	if err != nil {
		return 1, err
	}
	imported, err := config.FromLines(lines)
	if err != nil {
		return 1, err
	}
	imported.Connection = connection
	encoded := config.Encode(imported)

	if *output == "-" {
		_, err := a.stdout.Write(encoded)
		return boolCode(err), err
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if *force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	file, err := os.OpenFile(*output, flags, 0o644)
	if err != nil {
		return 1, fmt.Errorf("%w (use -force to overwrite)", err)
	}
	defer file.Close()
	if _, err := file.Write(encoded); err != nil {
		return 1, err
	}
	fmt.Fprintf(a.stderr, "Wrote %s\n", *output)
	return 0, nil
}

func boolCode(err error) int {
	if err != nil {
		return 1
	}
	return 0
}

func (a *app) runRender(args []string) (int, error) {
	fs := newFlagSet("render", a.stderr)
	path := fs.String("c", defaultConfigPath, "TOML config file")
	if done, code, err := parseFlags(fs, args); done {
		return code, err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return 1, err
	}
	context := ""
	for _, line := range cfg.Render() {
		if line.Context != context {
			if line.Context != "" {
				fmt.Fprintln(a.stdout, rtx.SelectCommand(line.Context))
			}
			context = line.Context
		}
		if line.Context != "" {
			fmt.Fprint(a.stdout, " ")
		}
		fmt.Fprintln(a.stdout, line.Text)
	}
	return 0, nil
}

func (a *app) runPlan(args []string) (int, error) {
	fs := newFlagSet("plan", a.stderr)
	path := fs.String("c", defaultConfigPath, "TOML config file")
	conn := addConnFlags(fs)
	fromFile := fs.String("from-file", "", "compare against show config output in a file instead of the router")
	detailed := fs.Bool("detailed-exitcode", false, "exit with 2 when there are changes")
	commands := fs.Bool("commands", false, "also print the exact commands apply would send")
	if done, code, err := parseFlags(fs, args); done {
		return code, err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return 1, err
	}
	conn.merge(&cfg.Connection)

	var current []rtx.Line
	if *fromFile != "" {
		current, err = readShowConfigFile(*fromFile)
	} else {
		current, err = a.readRouter(cfg.Connection)
	}
	if err != nil {
		return 1, err
	}
	p, err := plan.Diff(current, cfg.Render())
	if err != nil {
		return 1, err
	}
	a.printPlan(p)
	if *commands && !p.Empty() {
		fmt.Fprintln(a.stdout, "\nCommands:")
		for _, command := range p.Commands() {
			fmt.Fprintln(a.stdout, "  "+command)
		}
	}
	if *detailed && !p.Empty() {
		return exitChanges, nil
	}
	return 0, nil
}

func (a *app) printPlan(p *plan.Plan) {
	if p.Empty() {
		fmt.Fprintf(a.stdout, "No changes. The router matches the configuration. (%d protected lines ignored)\n", len(p.Protected))
		return
	}
	p.Write(a.stdout, isTerminal(a.stdout) && os.Getenv("NO_COLOR") == "")
	fmt.Fprintf(a.stdout, "%s (%d protected lines ignored)\n", p.Summary(), len(p.Protected))
	if risks := p.LockoutRisks(); len(risks) > 0 {
		fmt.Fprintln(a.stdout, "\nWarning: these changes could cut off remote access to the router:")
		for _, item := range risks {
			line := item.New
			if item.Action == plan.Remove {
				line = item.Old
			}
			fmt.Fprintf(a.stdout, "  %s %s\n", item.Action, line.Text)
		}
	}
}

func (a *app) runApply(args []string) (int, error) {
	fs := newFlagSet("apply", a.stderr)
	path := fs.String("c", defaultConfigPath, "TOML config file")
	conn := addConnFlags(fs)
	autoApprove := fs.Bool("auto-approve", false, "skip the confirmation prompt")
	allowLockout := fs.Bool("allow-lockout-risk", false, "allow -auto-approve even if changes could cut off remote access")
	noSave := fs.Bool("no-save", false, "do not save: changes are lost when the router restarts")
	if done, code, err := parseFlags(fs, args); done {
		return code, err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return 1, err
	}
	conn.merge(&cfg.Connection)
	desired := cfg.Render()

	s, err := a.dial(cfg.Connection)
	if err != nil {
		return 1, err
	}
	defer s.Close()
	if err := s.Become(); err != nil {
		return 1, err
	}
	current, err := s.ReadConfig()
	if err != nil {
		return 1, err
	}
	p, err := plan.Diff(current, desired)
	if err != nil {
		return 1, err
	}
	a.printPlan(p)
	if p.Empty() {
		return 0, nil
	}

	if *autoApprove {
		if len(p.LockoutRisks()) > 0 && !*allowLockout {
			return 1, errors.New("refusing to auto-approve changes that could cut off remote access (use -allow-lockout-risk)")
		}
	} else if !a.confirm() {
		fmt.Fprintln(a.stdout, "Apply cancelled.")
		return 1, nil
	}

	commands := p.Commands()
	for i, command := range commands {
		fmt.Fprintf(a.stdout, "[%d/%d] %s\n", i+1, len(commands), command)
		output, err := s.Exec(command)
		if err != nil {
			return 1, fmt.Errorf("apply stopped: %w\nNothing was saved. %d of %d commands took effect in the running config; restarting the router reverts them", err, i, len(commands))
		}
		if output != "" {
			fmt.Fprintln(a.stdout, output)
		}
	}

	if *noSave {
		fmt.Fprintln(a.stdout, "Not saved (-no-save): the changes are lost when the router restarts.")
	} else if err := s.Save(); err != nil {
		return 1, fmt.Errorf("commands applied, but save failed: %w", err)
	} else {
		fmt.Fprintln(a.stdout, "Saved.")
	}

	after, err := s.ReadConfig()
	if err != nil {
		return 1, fmt.Errorf("applied, but could not verify the result: %w", err)
	}
	residual, err := plan.Diff(after, desired)
	if err != nil {
		return 1, err
	}
	if !residual.Empty() {
		residual.Write(a.stdout, false)
		return 1, fmt.Errorf("applied, but %d differences remain. The router may drop default values or rewrite them (e.g. port numbers to names); match its form in the TOML file", len(residual.Items))
	}
	fmt.Fprintln(a.stdout, "Apply complete. The router matches the configuration.")
	return 0, nil
}

func (a *app) confirm() bool {
	fmt.Fprint(a.stdout, "\nType \"yes\" to apply these changes: ")
	answer, _ := bufio.NewReader(a.stdin).ReadString('\n')
	return strings.TrimSpace(answer) == "yes"
}

func readShowConfigFile(path string) ([]rtx.Line, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return rtx.ParseShowConfig(string(data)), nil
}

func (a *app) readRouter(connection config.Connection) ([]rtx.Line, error) {
	s, err := a.dial(connection)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	// How secrets are displayed may depend on privileges, so reads also always use administrator mode.
	if err := s.Become(); err != nil {
		return nil, err
	}
	return s.ReadConfig()
}

func (a *app) dial(connection config.Connection) (*session.Session, error) {
	knownHosts := connection.KnownHosts
	if knownHosts == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		knownHosts = filepath.Join(home, ".ssh", "known_hosts")
	}
	knownHosts, err := expandHome(knownHosts)
	if err != nil {
		return nil, err
	}
	identity, err := expandHome(connection.IdentityFile)
	if err != nil {
		return nil, err
	}
	// Skip the agent when the password is in the environment: trying keys one by one
	// can hit the authentication attempt limit and disconnect before the password is tried.
	_, hasPassword := os.LookupEnv("YAMARTX_PASSWORD")
	return session.Dial(session.Options{
		Host:          connection.Host,
		Port:          connection.Port,
		User:          connection.User,
		IdentityFile:  identity,
		KnownHosts:    knownHosts,
		UseAgent:      !hasPassword && identity == "",
		Password:      a.secret("YAMARTX_PASSWORD", "Login password: "),
		AdminPassword: a.secret("YAMARTX_ADMIN_PASSWORD", "Administrator password: "),
	})
}

func (a *app) secret(env, prompt string) func() (string, error) {
	return func() (string, error) {
		if value, ok := os.LookupEnv(env); ok {
			return value, nil
		}
		file, ok := a.stdin.(*os.File)
		if !ok || !term.IsTerminal(int(file.Fd())) {
			return "", fmt.Errorf("%s is not set and stdin is not a terminal", env)
		}
		fmt.Fprint(a.stderr, prompt)
		password, err := term.ReadPassword(int(file.Fd()))
		fmt.Fprintln(a.stderr)
		return string(password), err
	}
}

func expandHome(path string) (string, error) {
	rest, ok := strings.CutPrefix(path, "~/")
	if !ok {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, rest), nil
}

func isTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}
