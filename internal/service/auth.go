// Package service holds the application's business logic, sitting between the
// HTTP transport and the repositories.
package service

import (
	"context"
	"crypto/subtle"
	"strings"
	"time"

	"cannect/internal/auth"
	"cannect/internal/domain"
	"cannect/internal/email"
	"cannect/internal/facility/fault"
)

// UserRepository is the persistence contract the auth service depends on.
type UserRepository interface {
	Create(ctx context.Context, u *domain.User) error
	GetByID(ctx context.Context, id domain.ID) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	Update(ctx context.Context, u *domain.User) error
}

// ErrEmailNotVerified is returned by Login when the account exists and the
// password is correct but the email has not been verified yet. The handler
// turns it into a 403 + requiresVerification body (matches the web contract).
var ErrEmailNotVerified = fault.NewStringError("service.auth.Login", fault.Forbidden, "email not verified")

// AuthService implements registration, login, email verification, password
// reset and Google sign-in (with an email second factor).
type AuthService struct {
	users   UserRepository
	jwt     *auth.Manager
	google  *auth.Google
	mailer  email.Mailer
	codeTTL time.Duration
}

// AuthDeps bundles AuthService collaborators.
type AuthDeps struct {
	Users   UserRepository
	JWT     *auth.Manager
	Google  *auth.Google // may be nil / disabled
	Mailer  email.Mailer
	CodeTTL time.Duration
}

// NewAuthService builds an AuthService.
func NewAuthService(d AuthDeps) *AuthService {
	return &AuthService{
		users:   d.Users,
		jwt:     d.JWT,
		google:  d.Google,
		mailer:  d.Mailer,
		codeTTL: d.CodeTTL,
	}
}

// Register creates an unverified email/password account (or refreshes the code
// for an existing unverified one) and emails a verification code. Returns the
// normalized email so the caller can prompt for the code.
func (s *AuthService) Register(ctx context.Context, emailAddr, password string) (string, error) {
	const op fault.Op = "service.auth.Register"
	emailAddr = normalizeEmail(emailAddr)
	if emailAddr == "" || password == "" {
		return "", fault.NewStringError(op, fault.BadRequest, "email and password are required")
	}
	if _, ok := auth.ValidatePassword(password); !ok {
		return "", fault.NewStringError(op, fault.BadRequest,
			"password must be at least 8 characters and contain an uppercase letter, a number and a special character")
	}

	existing, err := s.users.GetByEmail(ctx, emailAddr)
	switch {
	case err == nil:
		// Google-linked account without a password — steer to Google sign-in.
		if existing.PasswordHash == "" || existing.AuthProvider == domain.AuthProviderGoogle {
			return "", fault.NewStringError(op, fault.AlreadyExist, "this email is connected to Google sign-in")
		}
		if existing.EmailVerified {
			return "", fault.NewStringError(op, fault.AlreadyExist, "user with this email already exists")
		}
		// Unverified: refresh password + code and resend.
		hash, herr := auth.HashPassword(password)
		if herr != nil {
			return "", fault.NewError(op, fault.Internal, herr)
		}
		existing.PasswordHash = hash
		if err := s.assignCode(ctx, op, existing, codeKindVerification); err != nil {
			return "", err
		}
		return existing.Email, nil
	case fault.Is(fault.NotFound, err):
		// fall through to create
	default:
		return "", err
	}

	hash, herr := auth.HashPassword(password)
	if herr != nil {
		return "", fault.NewError(op, fault.Internal, herr)
	}
	user := &domain.User{
		Email:         emailAddr,
		PasswordHash:  hash,
		AuthProvider:  domain.AuthProviderEmail,
		Role:          domain.RoleUser,
		EmailVerified: false,
	}
	code, expiry, gerr := s.newCode()
	if gerr != nil {
		return "", fault.NewError(op, fault.Internal, gerr)
	}
	user.VerificationCode = code
	user.VerificationCodeExpiry = expiry
	if err := s.users.Create(ctx, user); err != nil {
		return "", err
	}
	if err := s.mailer.SendVerificationCode(ctx, user.Email, code); err != nil {
		return "", fault.NewError(op, fault.Internal, err)
	}
	return user.Email, nil
}

// VerifyEmail confirms a registration code, marks the email verified and issues
// an access token.
func (s *AuthService) VerifyEmail(ctx context.Context, emailAddr, code string) (string, *domain.User, error) {
	const op fault.Op = "service.auth.VerifyEmail"
	user, err := s.requireUser(ctx, op, emailAddr)
	if err != nil {
		return "", nil, err
	}
	if user.EmailVerified {
		return "", nil, fault.NewStringError(op, fault.BadRequest, "email already verified")
	}
	if err := validateCode(op, user.VerificationCode, user.VerificationCodeExpiry, code); err != nil {
		return "", nil, err
	}
	user.EmailVerified = true
	user.VerificationCode = ""
	user.VerificationCodeExpiry = time.Time{}
	user.LastLogin = time.Now()
	if err := s.users.Update(ctx, user); err != nil {
		return "", nil, err
	}
	_ = s.mailer.SendWelcome(ctx, user.Email)
	return s.issueToken(op, user)
}

// ResendCode re-issues a verification code for an unverified account, enforcing
// a cooldown equal to the code TTL (matches the web 1-minute window).
func (s *AuthService) ResendCode(ctx context.Context, emailAddr string) error {
	const op fault.Op = "service.auth.ResendCode"
	user, err := s.requireUser(ctx, op, emailAddr)
	if err != nil {
		return err
	}
	if user.EmailVerified {
		return fault.NewStringError(op, fault.BadRequest, "email already verified")
	}
	if !user.VerificationCodeExpiry.IsZero() && user.VerificationCodeExpiry.After(time.Now()) {
		return fault.NewStringError(op, fault.RateLimited, "please wait before requesting a new code")
	}
	return s.assignCode(ctx, op, user, codeKindVerification)
}

// Login verifies email/password credentials and issues a token. Unverified
// accounts get ErrEmailNotVerified.
func (s *AuthService) Login(ctx context.Context, emailAddr, password string) (string, *domain.User, error) {
	const op fault.Op = "service.auth.Login"
	emailAddr = normalizeEmail(emailAddr)
	if emailAddr == "" || password == "" {
		return "", nil, fault.NewStringError(op, fault.BadRequest, "email and password are required")
	}
	user, err := s.users.GetByEmail(ctx, emailAddr)
	if err != nil {
		if fault.Is(fault.NotFound, err) {
			return "", nil, fault.NewStringError(op, fault.Unauthorized, "invalid credentials")
		}
		return "", nil, err
	}
	if user.PasswordHash == "" {
		return "", nil, fault.NewStringError(op, fault.AlreadyExist, "this email is connected to Google sign-in")
	}
	if !auth.ComparePassword(password, user.PasswordHash) {
		return "", nil, fault.NewStringError(op, fault.Unauthorized, "invalid credentials")
	}
	if !user.EmailVerified {
		return "", nil, ErrEmailNotVerified
	}
	user.LastLogin = time.Now()
	if err := s.users.Update(ctx, user); err != nil {
		return "", nil, err
	}
	return s.issueToken(op, user)
}

// Me returns the user behind an authenticated request.
func (s *AuthService) Me(ctx context.Context, userID string) (*domain.User, error) {
	const op fault.Op = "service.auth.Me"
	id, err := domain.ParseID(userID)
	if err != nil {
		return nil, fault.NewError(op, fault.Unauthorized, err)
	}
	return s.users.GetByID(ctx, id)
}

// ForgotPassword issues a password-reset code. It never reveals whether the
// email exists; the handler always returns a generic message.
func (s *AuthService) ForgotPassword(ctx context.Context, emailAddr string) error {
	const op fault.Op = "service.auth.ForgotPassword"
	emailAddr = normalizeEmail(emailAddr)
	if emailAddr == "" {
		return fault.NewStringError(op, fault.BadRequest, "email is required")
	}
	user, err := s.users.GetByEmail(ctx, emailAddr)
	if err != nil {
		if fault.Is(fault.NotFound, err) {
			return nil // do not disclose existence
		}
		return err
	}
	if user.PasswordHash == "" {
		return fault.NewStringError(op, fault.AlreadyExist, "this email is connected to Google sign-in")
	}
	return s.assignCode(ctx, op, user, codeKindReset)
}

// ResetPassword validates a reset code and sets a new password.
func (s *AuthService) ResetPassword(ctx context.Context, emailAddr, code, newPassword string) error {
	const op fault.Op = "service.auth.ResetPassword"
	if emailAddr == "" || code == "" || newPassword == "" {
		return fault.NewStringError(op, fault.BadRequest, "email, code and new password are required")
	}
	if _, ok := auth.ValidatePassword(newPassword); !ok {
		return fault.NewStringError(op, fault.BadRequest,
			"password must be at least 8 characters and contain an uppercase letter, a number and a special character")
	}
	user, err := s.requireUser(ctx, op, emailAddr)
	if err != nil {
		return err
	}
	if err := validateCode(op, user.PasswordResetCode, user.PasswordResetCodeExpiry, code); err != nil {
		return err
	}
	hash, herr := auth.HashPassword(newPassword)
	if herr != nil {
		return fault.NewError(op, fault.Internal, herr)
	}
	user.PasswordHash = hash
	user.PasswordResetCode = ""
	user.PasswordResetCodeExpiry = time.Time{}
	return s.users.Update(ctx, user)
}

// GoogleAuthURL returns the consent-screen URL, or an error when Google is off.
func (s *AuthService) GoogleAuthURL(state string) (string, error) {
	const op fault.Op = "service.auth.GoogleAuthURL"
	if s.google == nil || !s.google.Enabled() {
		return "", fault.NewStringError(op, fault.BadRequest, "google sign-in is not configured")
	}
	return s.google.AuthCodeURL(state), nil
}

// GoogleStartCallback exchanges the OAuth code, upserts the user and — as the
// second factor — emails a login code. Returns the normalized email; the caller
// completes the login with CompleteGoogleLogin once the user enters the code.
func (s *AuthService) GoogleStartCallback(ctx context.Context, code string) (string, error) {
	const op fault.Op = "service.auth.GoogleStartCallback"
	if s.google == nil || !s.google.Enabled() {
		return "", fault.NewStringError(op, fault.BadRequest, "google sign-in is not configured")
	}
	gu, err := s.google.Exchange(ctx, code)
	if err != nil {
		return "", fault.NewError(op, fault.Unauthorized, err)
	}
	return s.upsertGoogleAndSendCode(ctx, op, gu)
}

// GoogleStartIDToken is the mobile/one-tap counterpart of GoogleStartCallback:
// it verifies a Google ID token directly, upserts the user and emails the
// second-factor code.
func (s *AuthService) GoogleStartIDToken(ctx context.Context, idToken string) (string, error) {
	const op fault.Op = "service.auth.GoogleStartIDToken"
	if s.google == nil || !s.google.Enabled() {
		return "", fault.NewStringError(op, fault.BadRequest, "google sign-in is not configured")
	}
	if idToken == "" {
		return "", fault.NewStringError(op, fault.BadRequest, "idToken is required")
	}
	gu, err := s.google.VerifyIDToken(ctx, idToken)
	if err != nil {
		return "", fault.NewError(op, fault.Unauthorized, err)
	}
	return s.upsertGoogleAndSendCode(ctx, op, gu)
}

// CompleteGoogleLogin validates the emailed second-factor code for a Google
// sign-in and issues the access token.
func (s *AuthService) CompleteGoogleLogin(ctx context.Context, emailAddr, code string) (string, *domain.User, error) {
	const op fault.Op = "service.auth.CompleteGoogleLogin"
	user, err := s.requireUser(ctx, op, emailAddr)
	if err != nil {
		return "", nil, err
	}
	if err := validateCode(op, user.VerificationCode, user.VerificationCodeExpiry, code); err != nil {
		return "", nil, err
	}
	user.VerificationCode = ""
	user.VerificationCodeExpiry = time.Time{}
	user.LastLogin = time.Now()
	if err := s.users.Update(ctx, user); err != nil {
		return "", nil, err
	}
	return s.issueToken(op, user)
}

// --- helpers ---

func (s *AuthService) upsertGoogleAndSendCode(ctx context.Context, op fault.Op, gu *auth.GoogleUser) (string, error) {
	if !gu.EmailVerified {
		return "", fault.NewStringError(op, fault.Forbidden, "google email is not verified")
	}
	emailAddr := normalizeEmail(gu.Email)

	user, err := s.users.GetByEmail(ctx, emailAddr)
	switch {
	case err == nil:
		if user.GoogleID == "" {
			user.GoogleID = gu.Sub
		}
		if user.AuthProvider == "" {
			user.AuthProvider = domain.AuthProviderGoogle
		}
	case fault.Is(fault.NotFound, err):
		user = &domain.User{
			Email:         emailAddr,
			AuthProvider:  domain.AuthProviderGoogle,
			GoogleID:      gu.Sub,
			Role:          domain.RoleUser,
			EmailVerified: true,
		}
		if err := s.users.Create(ctx, user); err != nil {
			return "", err
		}
	default:
		return "", err
	}

	if err := s.assignCode(ctx, op, user, codeKindVerification); err != nil {
		return "", err
	}
	return user.Email, nil
}

type codeKind int

const (
	codeKindVerification codeKind = iota
	codeKindReset
)

// assignCode generates a fresh code, stores it on the right field, persists the
// user and emails it.
func (s *AuthService) assignCode(ctx context.Context, op fault.Op, user *domain.User, kind codeKind) error {
	code, expiry, err := s.newCode()
	if err != nil {
		return fault.NewError(op, fault.Internal, err)
	}
	switch kind {
	case codeKindReset:
		user.PasswordResetCode = code
		user.PasswordResetCodeExpiry = expiry
	default:
		user.VerificationCode = code
		user.VerificationCodeExpiry = expiry
	}
	if err := s.users.Update(ctx, user); err != nil {
		return err
	}
	if kind == codeKindReset {
		if err := s.mailer.SendPasswordResetCode(ctx, user.Email, code); err != nil {
			return fault.NewError(op, fault.Internal, err)
		}
		return nil
	}
	if err := s.mailer.SendVerificationCode(ctx, user.Email, code); err != nil {
		return fault.NewError(op, fault.Internal, err)
	}
	return nil
}

func (s *AuthService) newCode() (string, time.Time, error) {
	code, err := auth.GenerateVerificationCode()
	if err != nil {
		return "", time.Time{}, err
	}
	return code, time.Now().Add(s.codeTTL), nil
}

func (s *AuthService) issueToken(op fault.Op, user *domain.User) (string, *domain.User, error) {
	token, err := s.jwt.GenerateAccessToken(user.ID.Hex(), user.Email, string(user.Role))
	if err != nil {
		return "", nil, fault.NewError(op, fault.Internal, err)
	}
	return token, user, nil
}

func (s *AuthService) requireUser(ctx context.Context, op fault.Op, emailAddr string) (*domain.User, error) {
	emailAddr = normalizeEmail(emailAddr)
	if emailAddr == "" {
		return nil, fault.NewStringError(op, fault.BadRequest, "email is required")
	}
	user, err := s.users.GetByEmail(ctx, emailAddr)
	if err != nil {
		if fault.Is(fault.NotFound, err) {
			return nil, fault.NewStringError(op, fault.NotFound, "user not found")
		}
		return nil, err
	}
	return user, nil
}

// validateCode checks a stored code against the supplied one: presence, expiry
// and exact match.
func validateCode(op fault.Op, stored string, expiry time.Time, supplied string) error {
	if stored == "" || expiry.IsZero() {
		return fault.NewStringError(op, fault.BadRequest, "no code found, please request a new one")
	}
	if time.Now().After(expiry) {
		return fault.NewStringError(op, fault.BadRequest, "code expired, please request a new one")
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(supplied)) != 1 {
		return fault.NewStringError(op, fault.BadRequest, "invalid code")
	}
	return nil
}

func normalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
