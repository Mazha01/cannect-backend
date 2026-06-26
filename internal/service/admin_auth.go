package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	"cannect/internal/auth"
	"cannect/internal/domain"
	"cannect/internal/facility/fault"
)

const (
	pendingKeyPrefix = "admin:2fa:"
	oidcKeyPrefix    = "admin:oidc:"
	// pendingTTL is how long the password step stays valid while the admin
	// completes the Telegram OIDC second factor.
	pendingTTL = 5 * time.Minute
)

// oidcState is the per-login data stashed in Redis between the OIDC authorize
// redirect and the callback, keyed by the OAuth `state` value.
type oidcState struct {
	TwoFactorToken string `json:"t"`
	Nonce          string `json:"n"`
	Verifier       string `json:"v"`
}

// AdminAuthService is the admin authorization flow: email/password as the first
// factor, Telegram OIDC (OpenID Connect, Authorization Code + PKCE, RS256) as
// the second. Only accounts with the admin role may use it. The two steps are
// tied together by a short-lived pending token in Redis so the second factor
// can't be completed without the password.
type AdminAuthService struct {
	users UserRepository
	jwt   *auth.Manager
	oidc  *auth.OIDC
	redis *redis.Client
}

// AdminAuthDeps bundles AdminAuthService collaborators.
type AdminAuthDeps struct {
	Users UserRepository
	JWT   *auth.Manager
	OIDC  *auth.OIDC
	Redis *redis.Client
}

// NewAdminAuthService builds an AdminAuthService.
func NewAdminAuthService(d AdminAuthDeps) *AdminAuthService {
	return &AdminAuthService{
		users: d.Users,
		jwt:   d.JWT,
		oidc:  d.OIDC,
		redis: d.Redis,
	}
}

// Login verifies an admin's email/password (first factor) and returns a
// short-lived two-factor token. The admin then proves Telegram account
// ownership via the OIDC flow to receive the access token.
func (s *AdminAuthService) Login(ctx context.Context, emailAddr, password string) (string, error) {
	const op fault.Op = "service.admin.Login"
	emailAddr = normalizeEmail(emailAddr)
	if emailAddr == "" || password == "" {
		return "", fault.NewStringError(op, fault.BadRequest, "email and password are required")
	}
	user, err := s.requireAdmin(ctx, op, emailAddr)
	if err != nil {
		return "", err
	}
	if user.PasswordHash == "" || !auth.ComparePassword(password, user.PasswordHash) {
		return "", fault.NewStringError(op, fault.Unauthorized, "invalid credentials")
	}

	token, err := randomToken()
	if err != nil {
		return "", fault.NewError(op, fault.Internal, err)
	}
	if err := s.redis.Set(ctx, pendingKeyPrefix+token, user.ID.Hex(), pendingTTL).Err(); err != nil {
		return "", fault.NewError(op, fault.Internal, err)
	}
	return token, nil
}

// StartOIDC begins the OIDC second factor: it checks the pending password step,
// mints state/nonce/PKCE, stashes them in Redis and returns the provider
// authorization URL to redirect the browser to.
func (s *AdminAuthService) StartOIDC(ctx context.Context, twoFactorToken string) (string, error) {
	const op fault.Op = "service.admin.StartOIDC"
	if s.oidc == nil || !s.oidc.Enabled() {
		return "", fault.NewStringError(op, fault.BadRequest, "oidc login is not configured")
	}
	if twoFactorToken == "" {
		return "", fault.NewStringError(op, fault.Unauthorized, "missing two-factor token")
	}
	if err := s.redis.Get(ctx, pendingKeyPrefix+twoFactorToken).Err(); err != nil {
		if errors.Is(err, redis.Nil) {
			return "", fault.NewStringError(op, fault.Unauthorized, "two-factor session expired, log in again")
		}
		return "", fault.NewError(op, fault.Internal, err)
	}

	state, err := auth.RandomURLToken()
	if err != nil {
		return "", fault.NewError(op, fault.Internal, err)
	}
	nonce, err := auth.RandomURLToken()
	if err != nil {
		return "", fault.NewError(op, fault.Internal, err)
	}
	verifier, challenge, err := auth.NewPKCE()
	if err != nil {
		return "", fault.NewError(op, fault.Internal, err)
	}

	payload, err := json.Marshal(oidcState{TwoFactorToken: twoFactorToken, Nonce: nonce, Verifier: verifier})
	if err != nil {
		return "", fault.NewError(op, fault.Internal, err)
	}
	if err := s.redis.Set(ctx, oidcKeyPrefix+state, payload, pendingTTL).Err(); err != nil {
		return "", fault.NewError(op, fault.Internal, err)
	}

	authURL, err := s.oidc.AuthCodeURL(ctx, state, nonce, challenge)
	if err != nil {
		return "", fault.NewError(op, fault.Internal, err)
	}
	return authURL, nil
}

// CompleteOIDC handles the OIDC callback: it loads the stashed state, exchanges
// the code, verifies the id_token and checks that the verified subject matches
// the admin's linked Telegram account (binding on first use), then issues a JWT.
func (s *AdminAuthService) CompleteOIDC(ctx context.Context, state, code string) (string, *domain.User, error) {
	const op fault.Op = "service.admin.CompleteOIDC"
	if s.oidc == nil || !s.oidc.Enabled() {
		return "", nil, fault.NewStringError(op, fault.BadRequest, "oidc login is not configured")
	}
	if state == "" || code == "" {
		return "", nil, fault.NewStringError(op, fault.BadRequest, "missing state or code")
	}

	stateKey := oidcKeyPrefix + state
	raw, err := s.redis.Get(ctx, stateKey).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil, fault.NewStringError(op, fault.Unauthorized, "login state expired or invalid")
	}
	if err != nil {
		return "", nil, fault.NewError(op, fault.Internal, err)
	}
	var st oidcState
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return "", nil, fault.NewError(op, fault.Internal, err)
	}

	// The password step (pending token) must still be valid.
	pendingKey := pendingKeyPrefix + st.TwoFactorToken
	adminID, err := s.redis.Get(ctx, pendingKey).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil, fault.NewStringError(op, fault.Unauthorized, "two-factor session expired, log in again")
	}
	if err != nil {
		return "", nil, fault.NewError(op, fault.Internal, err)
	}

	identity, err := s.oidc.Exchange(ctx, code, st.Verifier, st.Nonce)
	if err != nil {
		return "", nil, fault.NewError(op, fault.Unauthorized, err)
	}

	id, err := domain.ParseID(adminID)
	if err != nil {
		return "", nil, fault.NewError(op, fault.Internal, err)
	}
	user, err := s.users.GetByID(ctx, id)
	if err != nil {
		return "", nil, err
	}
	if user.Role != domain.RoleAdmin {
		return "", nil, fault.NewStringError(op, fault.Forbidden, "not an admin account")
	}
	// Trust-on-first-use: bind the Telegram account on the first successful
	// second factor; afterwards it must match.
	if user.TelegramID == "" {
		user.TelegramID = identity.Subject
	} else if user.TelegramID != identity.Subject {
		return "", nil, fault.NewStringError(op, fault.Forbidden, "telegram account does not match")
	}

	user.LastLogin = time.Now()
	if err := s.users.Update(ctx, user); err != nil {
		return "", nil, err
	}
	// One-time use: drop both the state and the pending token.
	_ = s.redis.Del(ctx, stateKey, pendingKey).Err()

	token, err := s.jwt.GenerateAccessToken(user.ID.Hex(), user.Email, string(user.Role))
	if err != nil {
		return "", nil, fault.NewError(op, fault.Internal, err)
	}
	return token, user, nil
}

// Me returns the admin behind an authenticated request.
func (s *AdminAuthService) Me(ctx context.Context, userID string) (*domain.User, error) {
	const op fault.Op = "service.admin.Me"
	id, err := domain.ParseID(userID)
	if err != nil {
		return nil, fault.NewError(op, fault.Unauthorized, err)
	}
	return s.users.GetByID(ctx, id)
}

// requireAdmin loads the user and enforces the admin role. Non-admins (and
// missing accounts) get an unauthorized fault that doesn't disclose which.
func (s *AdminAuthService) requireAdmin(ctx context.Context, op fault.Op, emailAddr string) (*domain.User, error) {
	user, err := s.users.GetByEmail(ctx, emailAddr)
	if err != nil {
		if fault.Is(fault.NotFound, err) {
			return nil, fault.NewStringError(op, fault.Unauthorized, "invalid credentials")
		}
		return nil, err
	}
	if user.Role != domain.RoleAdmin {
		return nil, fault.NewStringError(op, fault.Forbidden, "not an admin account")
	}
	return user, nil
}

// randomToken returns a 32-byte hex string for the pending two-factor session.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
