// Package session drives the interactive shell of an RTX router over SSH.
//
// Like Yamaha's official Ansible collection (yamaha_network.rtx), it sends commands
// to a shell with a PTY and waits for the prompt.
package session

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/eggplants/yamartx/internal/rtx"
)

// QuietPeriod is how long output must stay silent before matching the prompt.
// It prevents a show config line that happens to end in > or # from being taken as the prompt.
// Only tests change it.
var QuietPeriod = 150 * time.Millisecond

var (
	promptRe      = regexp.MustCompile(`(?:^|\n)[^\n]*[>#] ?$`)
	adminPromptRe = regexp.MustCompile(`# ?$`)
	passwordRe    = regexp.MustCompile(`Password: ?$`)
	confirmRe     = regexp.MustCompile(`\(Y/N\)[^\n]*$`)
	ansiRe        = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)
	consoleRe     = regexp.MustCompile(`^console (lines|columns) `)
)

// consoleKeys are the settings changed temporarily while reading the configuration.
var consoleKeys = []string{"console lines", "console columns"}

// errorMarkers are the texts shown when a command fails. The language and encoding depend
// on console character, so the list has ASCII, UTF-8, Shift_JIS and EUC-JP forms.
var errorMarkers = []string{
	"error:",
	"エラー",
	"\x83\x47\x83\x89\x81\x5b",
	"\xa5\xa8\xa5\xe9\xa1\xbc",
}

// Options configures the connection.
type Options struct {
	Host         string
	Port         int
	User         string
	IdentityFile string
	KnownHosts   string
	// UseAgent also tries keys from ssh-agent.
	UseAgent bool
	// Password returns the login password when it is needed.
	Password func() (string, error)
	// AdminPassword returns the administrator password.
	AdminPassword func() (string, error)
	// Timeout limits the wait for one command's response. Zero means 60 seconds.
	Timeout time.Duration
}

// Session is a connection to an RTX router.
type Session struct {
	client  *ssh.Client
	ssh     *ssh.Session
	stdin   io.WriteCloser
	output  chan []byte
	timeout time.Duration
	admin   func() (string, error)
}

// Dial connects to the router and waits for the first prompt.
func Dial(o Options) (*Session, error) {
	if o.Host == "" || o.User == "" {
		return nil, errors.New("connection host and user are required (set [connection] or use -host/-user)")
	}
	if o.Port == 0 {
		o.Port = 22
	}
	if o.Timeout == 0 {
		o.Timeout = 60 * time.Second
	}
	hostKeys, err := knownhosts.New(o.KnownHosts)
	if err != nil {
		return nil, fmt.Errorf("read known hosts %s: %w", o.KnownHosts, err)
	}
	auth, err := authMethods(o)
	if err != nil {
		return nil, err
	}
	address := net.JoinHostPort(o.Host, strconv.Itoa(o.Port))
	client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{
		User:            o.User,
		Auth:            auth,
		HostKeyCallback: hostKeys,
		Timeout:         15 * time.Second,
	})
	if err != nil {
		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) && len(keyErr.Want) == 0 {
			return nil, fmt.Errorf("%s is not in %s; connect once with ssh to verify and add its host key: %w", o.Host, o.KnownHosts, err)
		}
		return nil, fmt.Errorf("connect to %s: %w", address, err)
	}

	s := &Session{client: client, output: make(chan []byte, 64), timeout: o.Timeout, admin: o.AdminPassword}
	if err := s.openShell(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func authMethods(o Options) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if o.IdentityFile != "" {
		key, err := os.ReadFile(o.IdentityFile)
		if err != nil {
			return nil, fmt.Errorf("read identity file: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("parse identity file %s: %w", o.IdentityFile, err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if socket := os.Getenv("SSH_AUTH_SOCK"); o.UseAgent && socket != "" {
		if conn, err := net.Dial("unix", socket); err == nil {
			methods = append(methods, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
		}
	}
	if o.Password != nil {
		methods = append(methods, ssh.PasswordCallback(o.Password))
	}
	return methods, nil
}

func (s *Session) openShell() error {
	session, err := s.client.NewSession()
	if err != nil {
		return fmt.Errorf("open session: %w", err)
	}
	s.ssh = session
	if err := session.RequestPty("vt100", 40, 200, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		return fmt.Errorf("request pty: %w", err)
	}
	s.stdin, err = session.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	if err := session.Shell(); err != nil {
		return fmt.Errorf("start shell: %w", err)
	}
	go func() {
		defer close(s.output)
		for {
			buf := make([]byte, 32*1024)
			n, err := stdout.Read(buf)
			if n > 0 {
				s.output <- buf[:n]
			}
			if err != nil {
				return
			}
		}
	}()
	if _, err := s.read(promptRe); err != nil {
		return fmt.Errorf("wait for prompt: %w", err)
	}
	return nil
}

// Close closes the connection. It sends no exit, so no prompt to save unsaved settings appears.
func (s *Session) Close() {
	if s.ssh != nil {
		_ = s.ssh.Close()
	}
	_ = s.client.Close()
}

func clean(raw []byte) string {
	text := ansiRe.ReplaceAllString(string(raw), "")
	return strings.ReplaceAll(text, "\r", "")
}

// read reads until output stops with one of the patterns matching at the end.
func (s *Session) read(patterns ...*regexp.Regexp) (string, error) {
	var buf []byte
	deadline := time.NewTimer(s.timeout)
	defer deadline.Stop()
	for {
		select {
		case chunk, ok := <-s.output:
			if !ok {
				return clean(buf), errors.New("connection closed by router")
			}
			buf = append(buf, chunk...)
		case <-time.After(QuietPeriod):
			text := clean(buf)
			for _, pattern := range patterns {
				if pattern.MatchString(text) {
					return text, nil
				}
			}
		case <-deadline.C:
			return clean(buf), fmt.Errorf("timed out after %s waiting for router", s.timeout)
		}
	}
}

func (s *Session) send(text string) error {
	_, err := io.WriteString(s.stdin, text+"\r")
	return err
}

// body strips the echoed command and the trailing prompt.
func body(text string) string {
	lines := strings.Split(text, "\n")
	if len(lines) < 2 {
		return ""
	}
	return strings.TrimSpace(strings.Join(lines[1:len(lines)-1], "\n"))
}

// Exec runs a configuration command and returns its output, or an error if the router reports one.
func (s *Session) Exec(command string) (string, error) {
	output, err := s.run(command)
	if err != nil {
		return output, err
	}
	lower := strings.ToLower(output)
	for _, marker := range errorMarkers {
		if strings.Contains(lower, marker) {
			return output, fmt.Errorf("%q: %s", command, output)
		}
	}
	return output, nil
}

// run runs a command and returns its output. Confirmation prompts are answered N and treated as failures.
func (s *Session) run(command string) (string, error) {
	if err := s.send(command); err != nil {
		return "", fmt.Errorf("send %q: %w", command, err)
	}
	text, err := s.read(promptRe, confirmRe)
	if err != nil {
		return "", fmt.Errorf("%q: %w", command, err)
	}
	if confirmRe.MatchString(text) {
		if err := s.send("N"); err != nil {
			return "", err
		}
		_, _ = s.read(promptRe)
		return "", fmt.Errorf("%q asked for confirmation and was declined: %s", command, strings.TrimSpace(text))
	}
	return body(text), nil
}

// Become enters administrator mode.
func (s *Session) Become() error {
	if err := s.send("administrator"); err != nil {
		return err
	}
	text, err := s.read(passwordRe, promptRe)
	if err != nil {
		return fmt.Errorf("administrator: %w", err)
	}
	if !passwordRe.MatchString(text) {
		if adminPromptRe.MatchString(text) {
			return nil
		}
		return fmt.Errorf("administrator: unexpected response: %s", strings.TrimSpace(text))
	}
	password, err := s.admin()
	if err != nil {
		return err
	}
	if err := s.send(password); err != nil {
		return err
	}
	text, err = s.read(promptRe, passwordRe)
	if err != nil {
		return fmt.Errorf("administrator: %w", err)
	}
	if !adminPromptRe.MatchString(text) {
		return errors.New("administrator: authentication failed")
	}
	return nil
}

// ReadConfig reads the current configuration as parsed lines.
func (s *Session) ReadConfig() ([]rtx.Line, error) {
	config, err := s.ShowConfig()
	if err != nil {
		return nil, err
	}
	return rtx.ParseShowConfig(config), nil
}

// ShowConfig returns the show config output as it would appear with the router's own console settings.
//
// It temporarily changes console lines and columns to stop paging and wrapping
// (the same method as the official Ansible collection). The change shows up in show config,
// so it is restored after reading and the result reports the original values.
func (s *Session) ShowConfig() (string, error) {
	// Display output may contain the word for error (in a description, say), so it is not scanned for errors.
	snapshot, err := s.run("show config | grep console")
	if err != nil {
		return "", err
	}
	original := map[string]string{}
	for _, line := range rtx.ParseShowConfig(snapshot) {
		if consoleRe.MatchString(line.Text) {
			original[line.Key()] = line.Text
		}
	}

	config, readErr := s.readWithoutPaging()
	if err := s.restoreConsole(original); err != nil && readErr == nil {
		readErr = fmt.Errorf("restore console settings: %w", err)
	}
	if readErr != nil {
		return "", readErr
	}
	return withOriginalConsole(config, original), nil
}

// withOriginalConsole replaces the temporary console lines in config with the original ones.
func withOriginalConsole(config string, original map[string]string) string {
	var lines []string
	seen := map[string]bool{}
	for _, line := range strings.Split(config, "\n") {
		if !consoleRe.MatchString(line) {
			lines = append(lines, line)
			continue
		}
		key := rtx.Line{Text: line}.Key()
		seen[key] = true
		if text, ok := original[key]; ok {
			lines = append(lines, text)
		}
	}
	for _, key := range consoleKeys {
		if text, ok := original[key]; ok && !seen[key] {
			lines = append(lines, text)
		}
	}
	return strings.Join(lines, "\n")
}

func (s *Session) readWithoutPaging() (string, error) {
	if _, err := s.Exec("console lines infinity"); err != nil {
		return "", err
	}
	// The limit is 200 or 4096 depending on the model, so try the wider one first.
	if _, err := s.Exec("console columns 4096"); err != nil {
		if _, err := s.Exec("console columns 200"); err != nil {
			return "", err
		}
	}
	config, err := s.run("show config")
	if err != nil {
		return "", err
	}
	// Misreading a non-config response could produce a plan that removes every setting.
	if !strings.HasPrefix(config, "#") {
		return "", fmt.Errorf("unexpected show config output: %.200q", config)
	}
	return config, nil
}

func (s *Session) restoreConsole(original map[string]string) error {
	for _, key := range consoleKeys {
		command := "no " + key
		if text, ok := original[key]; ok {
			command = text
		}
		if _, err := s.Exec(command); err != nil {
			return err
		}
	}
	return nil
}

// Save stores the configuration in non-volatile memory.
func (s *Session) Save() error {
	_, err := s.Exec("save")
	return err
}
