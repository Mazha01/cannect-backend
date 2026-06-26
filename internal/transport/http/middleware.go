package http

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"cannect/internal/auth"
	"cannect/internal/facility/fault"
)

// ctxKey avoids collisions in r.Context().
type ctxKey int

const ctxClaims ctxKey = iota

// ClaimsFromContext returns the authenticated token claims, or false.
func ClaimsFromContext(ctx context.Context) (*auth.Claims, bool) {
	c, ok := ctx.Value(ctxClaims).(*auth.Claims)
	return c, ok
}

// requireAuth validates the access token (cookie or Bearer header) and stores
// its claims in the request context.
func requireAuth(jwtMgr *auth.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := authenticate(jwtMgr, r)
			if !ok {
				writeError(w, r, fault.NewStringError("http.requireAuth", fault.Unauthorized, "invalid or missing token"))
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxClaims, claims)))
		})
	}
}

// requireRole is requireAuth plus a role check; used to gate the /admin group.
func requireRole(jwtMgr *auth.Manager, role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := authenticate(jwtMgr, r)
			if !ok {
				writeError(w, r, fault.NewStringError("http.requireRole", fault.Unauthorized, "invalid or missing token"))
				return
			}
			if claims.Role != role {
				writeError(w, r, fault.NewStringError("http.requireRole", fault.Forbidden, "insufficient privileges"))
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxClaims, claims)))
		})
	}
}

func authenticate(jwtMgr *auth.Manager, r *http.Request) (*auth.Claims, bool) {
	token := tokenFromRequest(r)
	if token == "" {
		return nil, false
	}
	claims, err := jwtMgr.Verify(token)
	if err != nil {
		return nil, false
	}
	return claims, true
}

// tokenFromRequest reads the JWT from the `token` cookie first, then the
// Authorization: Bearer header (mirrors the web read order).
func tokenFromRequest(r *http.Request) string {
	if c, err := r.Cookie("token"); err == nil && c.Value != "" {
		return c.Value
	}
	const prefix = "Bearer "
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// slogRequestLogger logs each request with status, latency and request id.
func slogRequestLogger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			start := time.Now()
			defer func() {
				log.LogAttrs(r.Context(), slog.LevelInfo, "http",
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.Int("status", ww.Status()),
					slog.Int("bytes", ww.BytesWritten()),
					slog.Duration("latency", time.Since(start)),
					slog.String("request_id", middleware.GetReqID(r.Context())),
					slog.String("remote", r.RemoteAddr),
				)
			}()
			next.ServeHTTP(ww, r)
		})
	}
}
