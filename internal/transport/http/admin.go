package http

import (
	"net/http"
	"time"

	"cannect/internal/service"
)

// AdminAuthHandler exposes the admin login flow: password + Telegram Login
// second factor.
type AdminAuthHandler struct {
	svc *service.AdminAuthService
	// oidcPostAuthURL, when set, is where the OIDC callback redirects after a
	// successful login (token passed in the URL fragment). Empty => JSON.
	oidcPostAuthURL string
}

// NewAdminAuthHandler builds an AdminAuthHandler. oidcPostAuthURL may be empty.
func NewAdminAuthHandler(svc *service.AdminAuthService, oidcPostAuthURL string) *AdminAuthHandler {
	return &AdminAuthHandler{svc: svc, oidcPostAuthURL: oidcPostAuthURL}
}

type adminLoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// Login — POST /admin/auth/login. First factor; returns a short-lived
// twoFactorToken the client presents together with the Telegram Login payload.
func (h *AdminAuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req adminLoginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	twoFactorToken, err := h.svc.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"requires2FA":    true,
		"channel":        "telegram_login",
		"twoFactorToken": twoFactorToken,
	})
}

// OIDCStart — GET /admin/auth/oidc/start?twoFactorToken=…. Redirects the browser
// to the Telegram OIDC consent screen (Authorization Code + PKCE).
func (h *AdminAuthHandler) OIDCStart(w http.ResponseWriter, r *http.Request) {
	twoFactorToken := r.URL.Query().Get("twoFactorToken")
	authURL, err := h.svc.StartOIDC(r.Context(), twoFactorToken)
	if err != nil {
		writeError(w, r, err)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// OIDCCallback — GET /admin/auth/oidc/callback?state=…&code=…. Completes the
// OIDC second factor and issues the admin token.
func (h *AdminAuthHandler) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		writeError(w, r, errBadRequest("oidc error: "+e))
		return
	}
	token, user, err := h.svc.CompleteOIDC(r.Context(), q.Get("state"), q.Get("code"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		MaxAge:   int((7 * 24 * time.Hour).Seconds()),
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
	})
	// When a post-auth URL is configured, bounce the browser there with the
	// token in the fragment (kept out of server logs / Referer).
	if h.oidcPostAuthURL != "" {
		http.Redirect(w, r, h.oidcPostAuthURL+"#token="+token, http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"accessToken": token,
		"user":        toUserResponse(user),
	})
}

// Me — GET /admin/auth/me (requires admin role).
func (h *AdminAuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, ErrorResponse{Error: "not authenticated"})
		return
	}
	user, err := h.svc.Me(r.Context(), claims.UserID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": toUserResponse(user)})
}
