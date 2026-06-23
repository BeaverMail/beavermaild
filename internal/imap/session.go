// IMAP session state machine for one client connection.
package imap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
)

type session struct {
	log   *slog.Logger
	conn  net.Conn
	r     *bufio.Reader
	dir   *directory.Local
	inbox *mail.Inbox

	principal directory.Principal
	selected  bool
	messages  []mail.Message
}

func newSession(log *slog.Logger, conn net.Conn, dir *directory.Local, inbox *mail.Inbox) *session {
	return &session{
		log:   log,
		conn:  conn,
		r:     bufio.NewReader(conn),
		dir:   dir,
		inbox: inbox,
	}
}

func (s *session) run(ctx context.Context) error {
	if err := s.untagged("OK BeaverMail IMAP4rev1 ready"); err != nil {
		return err
	}
	for {
		line, err := s.readLine()
		if err != nil {
			return err
		}
		if line == "" {
			continue
		}
		tag, cmd, arg := parseTagged(line)
		if tag == "" {
			continue
		}
		switch cmd {
		case "CAPABILITY":
			if err := s.untagged("CAPABILITY IMAP4rev1"); err != nil {
				return err
			}
			if err := s.tagged(tag, "OK CAPABILITY completed"); err != nil {
				return err
			}
		case "NOOP":
			if err := s.tagged(tag, "OK NOOP completed"); err != nil {
				return err
			}
		case "LOGIN":
			user, pass, ok := parseLogin(arg)
			if !ok {
				if err := s.tagged(tag, "BAD LOGIN requires user and password"); err != nil {
					return err
				}
				continue
			}
			p, err := s.dir.Authenticate(ctx, user, pass)
			if err != nil {
				if errors.Is(err, directory.ErrInvalidCredentials) || errors.Is(err, directory.ErrInactive) {
					if err := s.tagged(tag, "NO LOGIN failed"); err != nil {
						return err
					}
					continue
				}
				return err
			}
			s.principal = p
			s.selected = false
			s.messages = nil
			if err := s.tagged(tag, "OK LOGIN completed"); err != nil {
				return err
			}
		case "SELECT":
			if s.principal.AccountID == 0 {
				if err := s.tagged(tag, "NO LOGIN required"); err != nil {
					return err
				}
				continue
			}
			name := strings.TrimSpace(strings.ToUpper(arg))
			if name != "INBOX" {
				if err := s.tagged(tag, "NO mailbox does not exist"); err != nil {
					return err
				}
				continue
			}
			msgs, err := s.inbox.List(ctx, s.principal.AccountID, mail.InboxMailboxID)
			if err != nil {
				return err
			}
			s.messages = msgs
			s.selected = true
			if err := s.untagged(`FLAGS (\Seen)`); err != nil {
				return err
			}
			if err := s.untagged(fmt.Sprintf("%d EXISTS", len(msgs))); err != nil {
				return err
			}
			if err := s.untagged("0 RECENT"); err != nil {
				return err
			}
			if err := s.untagged("OK [UIDVALIDITY 1]"); err != nil {
				return err
			}
			if err := s.tagged(tag, "OK [READ-WRITE] SELECT completed"); err != nil {
				return err
			}
		case "FETCH":
			if !s.selected {
				if err := s.tagged(tag, "NO not selected"); err != nil {
					return err
				}
				continue
			}
			seq, items, ok := parseFetch(arg)
			if !ok {
				if err := s.tagged(tag, "BAD FETCH syntax"); err != nil {
					return err
				}
				continue
			}
			if seq < 1 || int(seq) > len(s.messages) {
				if err := s.tagged(tag, "OK FETCH completed"); err != nil {
					return err
				}
				continue
			}
			msg := s.messages[seq-1]
			if err := s.writeFetch(ctx, int(seq), msg, items); err != nil {
				return err
			}
			if err := s.tagged(tag, "OK FETCH completed"); err != nil {
				return err
			}
		case "LOGOUT":
			_ = s.untagged("BYE logging out")
			_ = s.tagged(tag, "OK LOGOUT completed")
			return nil
		default:
			if err := s.tagged(tag, "BAD command not supported"); err != nil {
				return err
			}
		}
	}
}

func (s *session) writeFetch(ctx context.Context, seq int, msg mail.Message, items fetchItems) error {
	var parts []string
	if items.uid {
		parts = append(parts, fmt.Sprintf("UID %d", msg.UID))
	}
	if items.flags {
		parts = append(parts, "FLAGS ()")
	}
	if items.size {
		parts = append(parts, fmt.Sprintf("RFC822.SIZE %d", msg.Meta.Size))
	}
	if items.body {
		raw, err := s.inbox.LoadRaw(ctx, msg.Meta)
		if err != nil {
			return err
		}
		parts = append(parts, fmt.Sprintf("BODY[] {%d}", len(raw)))
		if err := s.untagged(fmt.Sprintf("%d FETCH (%s", seq, strings.Join(parts, " "))); err != nil {
			return err
		}
		if _, err := s.conn.Write(raw); err != nil {
			return err
		}
		_, err = fmt.Fprintf(s.conn, ")\r\n")
		return err
	}
	return s.untagged(fmt.Sprintf("%d FETCH (%s)", seq, strings.Join(parts, " ")))
}

func (s *session) untagged(line string) error {
	_, err := fmt.Fprintf(s.conn, "* %s\r\n", line)
	return err
}

func (s *session) tagged(tag, resp string) error {
	_, err := fmt.Fprintf(s.conn, "%s %s\r\n", tag, resp)
	return err
}

func (s *session) readLine() (string, error) {
	line, err := s.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) > 8192 {
		return "", fmt.Errorf("imap: line too long")
	}
	return line, nil
}

func parseTagged(line string) (tag, cmd, arg string) {
	line = strings.TrimSpace(line)
	i := strings.IndexByte(line, ' ')
	if i < 0 {
		return "", strings.ToUpper(line), ""
	}
	tag = line[:i]
	rest := strings.TrimSpace(line[i+1:])
	j := strings.IndexByte(rest, ' ')
	if j < 0 {
		return tag, strings.ToUpper(rest), ""
	}
	return tag, strings.ToUpper(rest[:j]), strings.TrimSpace(rest[j+1:])
}

func parseLogin(arg string) (user, pass string, ok bool) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", "", false
	}
	if arg[0] == '"' {
		user, rest, found := parseQuoted(arg)
		if !found {
			return "", "", false
		}
		rest = strings.TrimSpace(rest)
		if rest == "" {
			return "", "", false
		}
		if rest[0] == '"' {
			pass, _, found = parseQuoted(rest)
			if !found {
				return "", "", false
			}
			return user, pass, true
		}
		return user, rest, true
	}
	i := strings.IndexByte(arg, ' ')
	if i < 0 {
		return "", "", false
	}
	return arg[:i], strings.TrimSpace(arg[i+1:]), true
}

func parseQuoted(s string) (val, rest string, ok bool) {
	if len(s) < 2 || s[0] != '"' {
		return "", "", false
	}
	end := 1
	for end < len(s) {
		if s[end] == '\\' && end+1 < len(s) {
			end += 2
			continue
		}
		if s[end] == '"' {
			return s[1:end], strings.TrimSpace(s[end+1:]), true
		}
		end++
	}
	return "", "", false
}

type fetchItems struct {
	uid, flags, size, body bool
}

func parseFetch(arg string) (seq uint32, items fetchItems, ok bool) {
	arg = strings.TrimSpace(arg)
	i := strings.IndexByte(arg, ' ')
	if i < 0 {
		n, err := strconv.ParseUint(arg, 10, 32)
		if err != nil {
			return 0, items, false
		}
		items.body = true
		return uint32(n), items, true
	}
	n, err := strconv.ParseUint(strings.TrimSpace(arg[:i]), 10, 32)
	if err != nil {
		return 0, items, false
	}
	rest := strings.ToUpper(arg[i:])
	items.uid = strings.Contains(rest, "UID")
	items.flags = strings.Contains(rest, "FLAGS")
	items.size = strings.Contains(rest, "RFC822.SIZE")
	items.body = strings.Contains(rest, "BODY[]") || strings.Contains(rest, "RFC822")
	return uint32(n), items, true
}
