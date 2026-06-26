package http

import (
	"errors"
	"net/http"
	"time"

	"cannect/internal/domain"
	"cannect/internal/service"
)

// AuthHandler exposes the email/password + Google sign-in endpoints.
type AuthHandler struct {
	svc *service.AuthService
	// googleRedirectURL is where the browser is sent after the Google callback
	// to enter the emailed second-factor code. Empty => respond with JSON.
	googleRedirectURL string
}

// NewAuthHandler builds an AuthHandler. googleRedirectURL may be empty.
func NewAuthHandler(svc *service.AuthService, googleRedirectURL string) *AuthHandler {
	return &AuthHandler{svc: svc, googleRedirectURL: googleRedirectURL}
}

// userResponse is the client-facing user shape (auth subset).
type userResponse struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Role          string `json:"role"`
	EmailVerified bool   `json:"emailVerified"`
}

func toUserResponse(u *domain.User) userResponse {
	return userResponse{
		ID:            u.ID.Hex(),
		Email:         u.Email,
		Role:          string(u.Role),
		EmailVerified: u.EmailVerified,
	}
}

type registerRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// Register — POST /auth/register.
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	emailAddr, err := h.svc.Register(r.Context(), req.Email, req.Password)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"requiresVerification": true,
		"email":                emailAddr,
	})
}

type verifyRequest struct {
	Email string `json:"email" validate:"required,email"`
	Code  string `json:"code" validate:"required"`
}

// VerifyEmail — POST /auth/verify-email.
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	token, user, err := h.svc.VerifyEmail(r.Context(), req.Email, req.Code)
	if err != nil {
		writeError(w, r, err)
		return
	}
	h.respondWithToken(w, token, user)
}

type emailOnlyRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ResendCode — POST /auth/resend-code.
func (h *AuthHandler) ResendCode(w http.ResponseWriter, r *http.Request) {
	var req emailOnlyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if err := h.svc.ResendCode(r.Context(), req.Email); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"message": "verification code sent", "email": req.Email})
}

type loginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// Login — POST /auth/login.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	token, user, err := h.svc.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		// Unverified accounts get a 403 + actionable body (web contract).
		if errors.Is(err, service.ErrEmailNotVerified) {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":                "email not verified",
				"requiresVerification": true,
				"email":                req.Email,
			})
			return
		}
		writeError(w, r, err)
		return
	}
	h.respondWithToken(w, token, user)
}

// Me — GET /auth/me (requires auth).
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
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

// Logout — POST /auth/logout. Stateless tokens: just clear the cookie.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// ForgotPassword — POST /auth/forgot-password.
func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req emailOnlyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if err := h.svc.ForgotPassword(r.Context(), req.Email); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message": "if an account exists with this email, a password reset code has been sent",
	})
}

type resetRequest struct {
	Email       string `json:"email" validate:"required,email"`
	Code        string `json:"code" validate:"required"`
	NewPassword string `json:"newPassword" validate:"required"`
}

// ResetPassword — POST /auth/reset-password.
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if err := h.svc.ResetPassword(r.Context(), req.Email, req.Code, req.NewPassword); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"message": "password reset successfully"})
}

// GoogleRedirect — GET /auth/google. Sends the browser to Google's consent.
func (h *AuthHandler) GoogleRedirect(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	authURL, err := h.svc.GoogleAuthURL(state)
	if err != nil {
		writeError(w, r, err)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// GoogleCallback — GET /auth/callback/google. Verifies the Google identity and
// issues the token directly (mirrors cannect-web). Sets the cookie and either
// redirects the browser to the configured post-auth URL with the token in the
// fragment, or returns JSON when no redirect URL is set.
func (h *AuthHandler) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	if e := r.URL.Query().Get("error"); e != "" {
		writeError(w, r, errBadRequest("google oauth error: "+e))
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		writeError(w, r, errBadRequest("missing code"))
		return
	}
	token, user, err := h.svc.GoogleCallback(r.Context(), code)
	if err != nil {
		writeError(w, r, err)
		return
	}
	setTokenCookie(w, token)
	if h.googleRedirectURL != "" {
		http.Redirect(w, r, h.googleRedirectURL+"#token="+token, http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"accessToken": token,
		"user":        toUserResponse(user),
	})
}

type googleMobileRequest struct {
	IDToken string `json:"idToken" validate:"required"`
}

// GoogleMobile — POST /auth/google/mobile. Verifies a Google ID token and issues
// the access token directly.
func (h *AuthHandler) GoogleMobile(w http.ResponseWriter, r *http.Request) {
	var req googleMobileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	token, user, err := h.svc.GoogleIDToken(r.Context(), req.IDToken)
	if err != nil {
		writeError(w, r, err)
		return
	}
	h.respondWithToken(w, token, user)
}

// setTokenCookie writes the auth cookie (non-httpOnly, mirrors the web side).
func setTokenCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		MaxAge:   int((7 * 24 * time.Hour).Seconds()),
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
	})
}

// respondWithToken sets the token cookie and returns the token + user in the body.
func (h *AuthHandler) respondWithToken(w http.ResponseWriter, token string, user *domain.User) {
	setTokenCookie(w, token)
	writeJSON(w, http.StatusOK, map[string]any{
		"accessToken": token,
		"user":        toUserResponse(user),
	})
}
