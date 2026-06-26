// Package email defines the Mailer abstraction used to deliver verification,
// password-reset and welcome messages, plus a development log-only sender.
package email

import (
	"context"
	"log/slog"
)

// Mailer sends transactional auth emails. Implementations may be SMTP, an API
// provider, or the no-op LogMailer used in development.
type Mailer interface {
	SendVerificationCode(ctx context.Context, to, code string) error
	SendPasswordResetCode(ctx context.Context, to, code string) error
	SendWelcome(ctx context.Context, to string) error
}

// LogMailer "sends" by logging — handy in development so codes appear in the
// server log without configuring an email provider.
type LogMailer struct {
	log *slog.Logger
}

// NewLogMailer builds a LogMailer.
func NewLogMailer(log *slog.Logger) *LogMailer {
	return &LogMailer{log: log}
}

func (m *LogMailer) SendVerificationCode(ctx context.Context, to, code string) error {
	m.log.InfoContext(ctx, "email: verification code", "to", to, "code", code)
	return nil
}

func (m *LogMailer) SendPasswordResetCode(ctx context.Context, to, code string) error {
	m.log.InfoContext(ctx, "email: password reset code", "to", to, "code", code)
	return nil
}

func (m *LogMailer) SendWelcome(ctx context.Context, to string) error {
	m.log.InfoContext(ctx, "email: welcome", "to", to)
	return nil
}
