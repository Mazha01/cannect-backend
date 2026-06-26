package email

import (
	"context"
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
)

// SMTPMailer sends real email over SMTP. Mirrors the cannect-web setup
// (nodemailer, port 465 implicit TLS by default). For port 587 it uses
// STARTTLS via smtp.SendMail.
type SMTPMailer struct {
	host     string
	port     int
	user     string
	password string
	from     string
}

// NewSMTPMailer builds an SMTPMailer. from defaults to user when empty.
func NewSMTPMailer(host string, port int, user, password, from string) *SMTPMailer {
	if from == "" {
		from = user
	}
	return &SMTPMailer{host: host, port: port, user: user, password: password, from: from}
}

// Enabled reports whether SMTP is configured.
func (m *SMTPMailer) Enabled() bool {
	return m.host != "" && m.user != ""
}

func (m *SMTPMailer) SendVerificationCode(_ context.Context, to, code string) error {
	return m.send(to, "Verify Your Email - CANNECT.AI", verificationHTML(code))
}

func (m *SMTPMailer) SendPasswordResetCode(_ context.Context, to, code string) error {
	return m.send(to, "Reset Your Password - CANNECT.AI", passwordResetHTML(code))
}

func (m *SMTPMailer) SendWelcome(_ context.Context, to string) error {
	return m.send(to, "Welcome to CANNECT.AI! 🎉", welcomeHTML())
}

func (m *SMTPMailer) send(to, subject, htmlBody string) error {
	msg := buildMessage(m.from, to, subject, htmlBody)
	addr := net.JoinHostPort(m.host, strconv.Itoa(m.port))
	auth := smtp.PlainAuth("", m.user, m.password, m.host)

	if m.port == 465 {
		return m.sendImplicitTLS(addr, auth, to, msg)
	}
	// 587 / other → STARTTLS handled by smtp.SendMail.
	return smtp.SendMail(addr, auth, m.from, []string{to}, msg)
}

// sendImplicitTLS handles port 465 (TLS from the first byte).
func (m *SMTPMailer) sendImplicitTLS(addr string, auth smtp.Auth, to string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: m.host})
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer func() { _ = c.Close() }()

	if err := c.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err := c.Mail(m.from); err != nil {
		return fmt.Errorf("smtp mail: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close: %w", err)
	}
	return c.Quit()
}

func buildMessage(from, to, subject, html string) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("UTF-8", subject) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(html)
	return []byte(b.String())
}

func verificationHTML(code string) string {
	return baseHTML("Verify your email",
		"Use the code below to verify your email address. It expires in 1 minute.", code)
}

func passwordResetHTML(code string) string {
	return baseHTML("Reset your password",
		"Use the code below to reset your password. It expires in 1 minute.", code)
}

func welcomeHTML() string {
	return `<div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto;padding:24px">
<h2>Welcome to CANNECT.AI 🎉</h2>
<p>Your email is verified and your account is ready.</p>
</div>`
}

func baseHTML(title, intro, code string) string {
	return fmt.Sprintf(`<div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto;padding:24px">
<h2>%s</h2>
<p>%s</p>
<div style="font-size:32px;font-weight:700;letter-spacing:6px;text-align:center;padding:16px;background:#f3f4f6;border-radius:10px;margin:16px 0">%s</div>
<p style="color:#666;font-size:12px">If you didn't request this, you can ignore this email.</p>
</div>`, title, intro, code)
}
