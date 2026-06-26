// Package config loads runtime configuration from environment variables.
package config

import (
	"fmt"
	"time"

	"github.com/caarlos0/env/v10"
	"github.com/joho/godotenv"
)

// Config bundles every runtime knob the binary needs.
type Config struct {
	Env      string `env:"ENV" envDefault:"development"`
	HTTP     HTTP
	Mongo    Mongo
	Redis    Redis
	Auth     Auth
	Google   Google
	Telegram Telegram
	SMTP     SMTP
	Log      Log
}

// SMTP configures outbound email (verification / reset / welcome). Mirrors the
// cannect-web env names. When Host + User are empty, the app falls back to the
// dev LogMailer (codes printed to the log instead of sent).
type SMTP struct {
	Host     string `env:"SMTP_HOST" envDefault:""`
	Port     int    `env:"SMTP_PORT" envDefault:"465"`
	User     string `env:"SMTP_USER" envDefault:""`
	Password string `env:"SMTP_PASSWORD" envDefault:""`
	From     string `env:"EMAIL_FROM" envDefault:""`
}

type HTTP struct {
	Port            string        `env:"PORT" envDefault:"8080"`
	ReadTimeout     time.Duration `env:"HTTP_READ_TIMEOUT" envDefault:"10s"`
	WriteTimeout    time.Duration `env:"HTTP_WRITE_TIMEOUT" envDefault:"15s"`
	IdleTimeout     time.Duration `env:"HTTP_IDLE_TIMEOUT" envDefault:"60s"`
	ShutdownTimeout time.Duration `env:"HTTP_SHUTDOWN_TIMEOUT" envDefault:"15s"`
	RequestTimeout  time.Duration `env:"HTTP_REQUEST_TIMEOUT" envDefault:"30s"`
}

// Mongo configures the MongoDB connection. URI is a standard connection
// string (mongodb:// or mongodb+srv://); Database is the default database the
// repositories operate on.
type Mongo struct {
	URI            string        `env:"MONGO_URI" envDefault:"mongodb://localhost:27017"`
	Database       string        `env:"MONGO_DB" envDefault:"cannect"`
	ConnectTimeout time.Duration `env:"MONGO_CONNECT_TIMEOUT" envDefault:"10s"`
	MaxPoolSize    uint64        `env:"MONGO_MAX_POOL_SIZE" envDefault:"100"`
	MinPoolSize    uint64        `env:"MONGO_MIN_POOL_SIZE" envDefault:"2"`
}

type Redis struct {
	Addr     string `env:"REDIS_ADDR" envDefault:"localhost:6379"`
	Password string `env:"REDIS_PASSWORD" envDefault:""`
	DB       int    `env:"REDIS_DB" envDefault:"0"`
}

type Auth struct {
	// JWTSecret signs/verifies access tokens (HS256). Mirrors NEXTAUTH_SECRET
	// on the web side — set both to the same value to share tokens.
	JWTSecret string `env:"JWT_SECRET" envDefault:"your-secret-key-here"`
	// AccessTokenTTL is the access-token lifetime (web uses 7d).
	AccessTokenTTL time.Duration `env:"ACCESS_TOKEN_TTL" envDefault:"168h"`
	// VerificationCodeTTL is how long an email / password-reset code stays
	// valid (web uses 1 minute).
	VerificationCodeTTL time.Duration `env:"VERIFICATION_CODE_TTL" envDefault:"1m"`
}

// Google configures Google OAuth sign-in. Sign-in is enabled only when both
// ClientID and ClientSecret are set.
type Google struct {
	ClientID     string `env:"GOOGLE_CLIENT_ID" envDefault:""`
	ClientSecret string `env:"GOOGLE_CLIENT_SECRET" envDefault:""`
	// RedirectURL must match the authorized redirect URI in Google Console and
	// point at GET /auth/callback/google on this service.
	RedirectURL string `env:"GOOGLE_REDIRECT_URL" envDefault:"http://localhost:8080/auth/callback/google"`
	// PostAuthURL is where the browser is sent after the callback to enter the
	// emailed second-factor code. Empty => the callback returns JSON instead.
	PostAuthURL string `env:"GOOGLE_POST_AUTH_URL" envDefault:""`
}

// Telegram configures the admin second factor via Telegram OIDC (OpenID
// Connect, Authorization Code + PKCE, RS256). Admin auth is enabled when
// ClientID + ClientSecret are set. Get them in @BotFather → Bot Settings →
// Web Login, and register the redirect URL there.
type Telegram struct {
	OIDCIssuer       string `env:"TELEGRAM_OIDC_ISSUER" envDefault:"https://oauth.telegram.org"`
	OIDCClientID     string `env:"TELEGRAM_OIDC_CLIENT_ID" envDefault:""`
	OIDCClientSecret string `env:"TELEGRAM_OIDC_CLIENT_SECRET" envDefault:""`
	OIDCRedirectURL  string `env:"TELEGRAM_OIDC_REDIRECT_URL" envDefault:"http://localhost:8080/admin/auth/oidc/callback"`
	// Explicit OIDC endpoints (Telegram does not publish a discovery doc).
	OIDCAuthURL  string `env:"TELEGRAM_OIDC_AUTH_URL" envDefault:"https://oauth.telegram.org/auth"`
	OIDCTokenURL string `env:"TELEGRAM_OIDC_TOKEN_URL" envDefault:"https://oauth.telegram.org/token"`
	OIDCJWKSURI  string `env:"TELEGRAM_OIDC_JWKS_URI" envDefault:"https://oauth.telegram.org/.well-known/jwks.json"`
	// OIDCPostAuthURL, when set, is where the callback redirects the browser
	// after a successful login, passing the token in the URL fragment
	// (#token=…). Empty => the callback returns the token as JSON. Point this
	// at the dev page (…/dev/telegram-login) to see the result rendered.
	OIDCPostAuthURL string `env:"TELEGRAM_OIDC_POST_AUTH_URL" envDefault:""`
}

type Log struct {
	Level  string `env:"LOG_LEVEL" envDefault:"info"`
	Format string `env:"LOG_FORMAT" envDefault:"json"`
}

// Load reads .env (if present) and parses environment into Config.
func Load() (*Config, error) {
	_ = godotenv.Load()
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("parse env: %w", err)
	}
	return cfg, nil
}
