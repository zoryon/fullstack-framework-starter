package email

import (
	"crypto/tls"
	"context"
	"fmt"
	"net/smtp"
	"strings"
)

// Sender is a minimal email transport used by auth flows.
type Sender interface {
	Send(ctx context.Context, to, subject, body string) error
}

// SMTPSender sends email via standard SMTP using Go stdlib.
type SMTPSender struct {
	host string
	port int
	user string
	pass string
	from string
}

func NewSMTPSender(host string, port int, user, pass, from string) (*SMTPSender, error) {
	host = strings.TrimSpace(host)
	user = strings.TrimSpace(user)
	from = strings.TrimSpace(from)

	if host == "" || port <= 0 || user == "" || pass == "" || from == "" {
		return nil, fmt.Errorf("smtp is not fully configured")
	}

	return &SMTPSender{
		host: host,
		port: port,
		user: user,
		pass: pass,
		from: from,
	}, nil
}

func (s *SMTPSender) Send(ctx context.Context, to, subject, body string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	to = strings.TrimSpace(to)
	if to == "" {
		return fmt.Errorf("missing recipient")
	}

	msg := buildMessage(s.from, to, subject, body)

	ports := []int{s.port}
	if s.port == 587 {
		ports = append(ports, 465)
	}

	var lastErr error
	for _, p := range ports {
		if err := s.sendOnPort(to, msg, p); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}

	return fmt.Errorf("send smtp mail: %w", lastErr)
}

func (s *SMTPSender) sendOnPort(to, msg string, port int) error {
	if port == 465 {
		return s.sendImplicitTLS(to, msg, port)
	}

	auth := smtp.PlainAuth("", s.user, s.pass, s.host)
	addr := fmt.Sprintf("%s:%d", s.host, port)
	return smtp.SendMail(addr, auth, s.from, []string{to}, []byte(msg))
}

func (s *SMTPSender) sendImplicitTLS(to, msg string, port int) error {
	addr := fmt.Sprintf("%s:%d", s.host, port)
	tlsCfg := &tls.Config{ServerName: s.host}

	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return err
	}
	defer client.Close()

	auth := smtp.PlainAuth("", s.user, s.pass, s.host)
	if err := client.Auth(auth); err != nil {
		return err
	}
	if err := client.Mail(s.from); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}

	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}

	return client.Quit()
}

func buildMessage(from, to, subject, body string) string {
	return strings.Join([]string{
		"From: " + from,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")
}
