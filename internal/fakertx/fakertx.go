// Package fakertx is an SSH server that imitates an RTX router for tests.
//
// It reproduces real behavior only as far as the official Ansible collection and the
// command reference describe it: prompts, administrator mode, pager, contexts and errors.
package fakertx

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/eggplants/yamartx/internal/rtx"
)

// Fixed credentials.
const (
	User          = "operator"
	Password      = "login-secret"
	AdminPassword = "admin-secret"
)

// Server imitates one router.
type Server struct {
	Host       string
	Port       int
	KnownHosts string

	// FailOn makes commands containing it return a Japanese error.
	FailOn string
	// ConfirmOn makes commands containing it ask for Y/N confirmation.
	ConfirmOn string
	// DropOn drops the connection on commands containing it (as when a change locks us out).
	DropOn string
	// MaxColumns is the upper limit of console columns.
	MaxColumns int
	// Rewrite rewrites accepted commands into the form a real router would display.
	Rewrite func(string) string
	// ShowConfigOutput replaces the show config output when non-empty.
	ShowConfigOutput string

	mu       sync.Mutex
	lines    []rtx.Line
	saved    []rtx.Line
	commands []string
}

// Start starts the server. The initial configuration is given in show config format.
func Start(t *testing.T, showConfig string) *Server {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if meta.User() == User && string(password) == Password {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		},
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	address := listener.Addr().(*net.TCPAddr)
	s := &Server{
		Host:       "127.0.0.1",
		Port:       address.Port,
		KnownHosts: filepath.Join(t.TempDir(), "known_hosts"),
		MaxColumns: 4096,
		lines:      rtx.ParseShowConfig(showConfig),
	}
	s.saved = slices.Clone(s.lines)
	entry := fmt.Sprintf("[127.0.0.1]:%d %s", address.Port, ssh.MarshalAuthorizedKey(signer.PublicKey()))
	if err := os.WriteFile(s.KnownHosts, []byte(entry), 0o600); err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go s.handle(conn, config)
		}
	}()
	return s
}

// Lines returns the current running config.
func (s *Server) Lines() []rtx.Line {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.lines)
}

// Saved returns the most recently saved configuration.
func (s *Server) Saved() []rtx.Line {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.saved)
}

// Commands returns the history of accepted commands.
func (s *Server) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.commands)
}

func (s *Server) handle(conn net.Conn, config *ssh.ServerConfig) {
	server, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer server.Close()
	go ssh.DiscardRequests(requests)
	for incoming := range channels {
		if incoming.ChannelType() != "session" {
			_ = incoming.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		channel, chanRequests, err := incoming.Accept()
		if err != nil {
			return
		}
		go func() {
			for request := range chanRequests {
				_ = request.Reply(request.Type == "pty-req" || request.Type == "shell", nil)
			}
		}()
		s.shell(channel)
		_ = channel.Close()
		return
	}
}

type shellState struct {
	admin    bool
	context  string
	pending  func(string)
	writeOut func(string)
}

func (st *shellState) prompt() string {
	suffix := "> "
	if st.admin {
		suffix = "# "
	}
	if id, ok := strings.CutPrefix(st.context, "tunnel "); ok {
		return "tunnel" + id + suffix
	}
	if id, ok := strings.CutPrefix(st.context, "pp "); ok {
		return "pp" + id + suffix
	}
	return suffix
}

func (s *Server) shell(channel ssh.Channel) {
	st := &shellState{writeOut: func(text string) { _, _ = channel.Write([]byte(strings.ReplaceAll(text, "\n", "\r\n"))) }}
	st.writeOut("\nRTX830 Rev.15.02.33\n\n" + st.prompt())

	var line []byte
	buf := make([]byte, 1024)
	for {
		n, err := channel.Read(buf)
		if err != nil {
			return
		}
		for _, b := range buf[:n] {
			if b != '\r' && b != '\n' {
				line = append(line, b)
				continue
			}
			text := string(line)
			line = line[:0]
			if st.pending != nil {
				pending := st.pending
				st.pending = nil
				pending(text)
				continue
			}
			st.writeOut(text + "\n")
			if s.DropOn != "" && strings.Contains(text, s.DropOn) {
				return
			}
			s.run(st, text)
		}
	}
}

func (s *Server) run(st *shellState, command string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commands = append(s.commands, command)
	reply := func(text string) { st.writeOut(text + st.prompt()) }

	switch {
	case command == "administrator":
		st.writeOut("Password: ")
		st.pending = func(password string) {
			st.admin = password == AdminPassword
			if !st.admin {
				st.writeOut("\nPassword: ")
				st.pending = func(string) {}
				return
			}
			st.writeOut("\n" + st.prompt())
		}
	case s.ConfirmOn != "" && strings.Contains(command, s.ConfirmOn):
		st.writeOut("Are you sure? (Y/N)")
		st.pending = func(string) { st.writeOut("\n" + st.prompt()) }
	case s.FailOn != "" && strings.Contains(command, s.FailOn):
		reply("エラー: パラメータが不正です\n")
	case command == "show config | grep console":
		var out strings.Builder
		for _, line := range s.lines {
			if strings.HasPrefix(line.Text, "console ") {
				out.WriteString(line.Text + "\n")
			}
		}
		reply(out.String())
	case command == "show config":
		if !s.hasLine("console lines infinity") {
			st.writeOut("# RTX830\n---つづく---") // A real router would wait for a key press here
			return
		}
		if s.ShowConfigOutput != "" {
			reply(s.ShowConfigOutput)
			return
		}
		reply(s.showConfig())
	case strings.HasPrefix(command, "console columns "):
		columns, err := strconv.Atoi(strings.TrimPrefix(command, "console columns "))
		if err != nil || columns > s.MaxColumns {
			reply("エラー: パラメータの値が不正です\n")
			return
		}
		s.apply("", command)
		reply("")
	case strings.HasPrefix(command, "console ") || strings.HasPrefix(command, "no console "):
		s.apply("", command) // Also allowed for non-administrators
		reply("")
	case !st.admin:
		reply("エラー: 管理パスワードで認証されていません\n")
	case command == "save":
		s.saved = slices.Clone(s.lines)
		reply("セーブ中... CONFIG0 終了\n")
	case command == "tunnel select none" || command == "pp select none":
		st.context = ""
		reply("")
	case strings.HasPrefix(command, "tunnel select ") || strings.HasPrefix(command, "pp select "):
		f := strings.Fields(command)
		st.context = f[0] + " " + f[2]
		reply("")
	default:
		if s.Rewrite != nil {
			command = s.Rewrite(command)
		}
		if err := s.apply(st.context, command); err != nil {
			reply("エラー: " + err.Error() + "\n")
			return
		}
		reply("")
	}
}

func (s *Server) hasLine(text string) bool {
	return slices.ContainsFunc(s.lines, func(line rtx.Line) bool { return line.Text == text })
}

func (s *Server) apply(context, command string) error {
	if target, ok := strings.CutPrefix(command, "no "); ok {
		key := rtx.Line{Text: target}.Key()
		index := slices.IndexFunc(s.lines, func(line rtx.Line) bool {
			return line.Context == context && line.Key() == key
		})
		if index < 0 {
			if strings.HasPrefix(target, "console ") {
				return nil // Removing an unset value does not fail
			}
			return fmt.Errorf("no such setting: %s", target)
		}
		s.lines = slices.Delete(s.lines, index, index+1)
		return nil
	}
	next := rtx.Line{Context: context, Text: command}
	index := slices.IndexFunc(s.lines, func(line rtx.Line) bool {
		return line.Context == context && line.Key() == next.Key()
	})
	if index >= 0 {
		s.lines[index] = next
	} else {
		s.lines = append(s.lines, next)
	}
	return nil
}

func (s *Server) showConfig() string {
	var out strings.Builder
	out.WriteString("# RTX830 Rev.15.02.33\n")
	context := ""
	for _, line := range s.lines {
		if line.Context != "" && line.Context != context {
			out.WriteString(rtx.SelectCommand(line.Context) + "\n")
		}
		context = line.Context
		text := line.Text
		if line.Context != "" {
			text = " " + text
		}
		out.WriteString(wrap(text, s.consoleColumns()-1) + "\n")
	}
	return out.String()
}

// consoleColumns returns the console width in effect. The default is 80.
func (s *Server) consoleColumns() int {
	for _, line := range s.lines {
		if value, ok := strings.CutPrefix(line.Text, "console columns "); ok {
			if columns, err := strconv.Atoi(value); err == nil {
				return columns
			}
		}
	}
	return 80
}

// wrap breaks text every width characters with no continuation marker, as a real router does.
func wrap(text string, width int) string {
	runes := []rune(text)
	var parts []string
	for len(runes) > width {
		parts = append(parts, string(runes[:width]))
		runes = runes[width:]
	}
	return strings.Join(append(parts, string(runes)), "\n")
}
