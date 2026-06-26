package http

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"cannect/internal/auth"
	"cannect/internal/config"
	"cannect/internal/database"
)

// Deps bundles every collaborator the router needs. Handlers are added here as
// the API grows.
type Deps struct {
	DB      *database.DB
	Logger  *slog.Logger
	HTTPCfg config.HTTP
	JWT     *auth.Manager
	Auth    *AuthHandler
	Admin   *AdminAuthHandler
	// DevPages mounts development-only helper pages (e.g. the Telegram login
	// test page). Never enable in production.
	DevPages bool
}

// NewRouter wires routes and middleware.
func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(slogRequestLogger(d.Logger))
	r.Use(middleware.Recoverer)
	r.Use(middleware.Compress(5))
	r.Use(middleware.Heartbeat("/ping"))
	r.Use(middleware.Timeout(d.HTTPCfg.RequestTimeout))

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Get("/readyz", readiness(d.DB))

	// User auth — email/password + Google sign-in (email second factor).
	if d.Auth != nil {
		r.Route("/auth", func(r chi.Router) {
			r.Post("/register", d.Auth.Register)
			r.Post("/verify-email", d.Auth.VerifyEmail)
			r.Post("/resend-code", d.Auth.ResendCode)
			r.Post("/login", d.Auth.Login)
			r.Post("/logout", d.Auth.Logout)
			r.Post("/forgot-password", d.Auth.ForgotPassword)
			r.Post("/reset-password", d.Auth.ResetPassword)

			// Google OAuth (with emailed second factor).
			r.Get("/google", d.Auth.GoogleRedirect)
			r.Get("/callback/google", d.Auth.GoogleCallback)
			r.Post("/google/mobile", d.Auth.GoogleMobile)
			r.Post("/google/verify", d.Auth.GoogleVerify)

			// Authenticated.
			r.Group(func(r chi.Router) {
				r.Use(requireAuth(d.JWT))
				r.Get("/me", d.Auth.Me)
			})
		})
	}

	// Admin auth — password + Telegram second factor, gated separately.
	if d.Admin != nil {
		r.Route("/admin", func(r chi.Router) {
			r.Post("/auth/login", d.Admin.Login)
			// Second factor — Telegram OIDC (Authorization Code + PKCE, RS256).
			r.Get("/auth/oidc/start", d.Admin.OIDCStart)
			r.Get("/auth/oidc/callback", d.Admin.OIDCCallback)

			// Admin-only area (role must be "admin").
			r.Group(func(r chi.Router) {
				r.Use(requireRole(d.JWT, "admin"))
				r.Get("/auth/me", d.Admin.Me)
			})
		})
	}

	// Development-only browser helper for the Telegram login flow.
	if d.DevPages && d.Admin != nil {
		r.Get("/dev/telegram-login", devTelegramLoginPage)
	}

	return r
}

// readiness verifies MongoDB is reachable before reporting ready.
func readiness(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := db.Ping(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "database unreachable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	}
}
