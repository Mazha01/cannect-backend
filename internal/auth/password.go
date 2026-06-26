// Package auth provides password hashing, JWT issuance/verification and
// verification-code generation — the primitives behind the auth flow.
package auth

import (
	"regexp"

	"golang.org/x/crypto/bcrypt"
)

// bcryptCost matches the web side (bcryptjs SALT_ROUNDS = 10).
const bcryptCost = 10

// HashPassword returns a bcrypt hash of the plaintext password.
func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ComparePassword reports whether password matches the stored hash.
func ComparePassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

var (
	reUppercase = regexp.MustCompile(`[A-Z]`)
	reNumber    = regexp.MustCompile(`[0-9]`)
	reSpecial   = regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]`)
)

// PasswordRequirements reports which strength rules a password satisfies.
// Mirrors src/lib/utils/password.ts on the web side.
type PasswordRequirements struct {
	MinLength      bool `json:"minLength"`
	HasUppercase   bool `json:"hasUppercase"`
	HasNumber      bool `json:"hasNumber"`
	HasSpecialChar bool `json:"hasSpecialChar"`
}

// ValidatePassword checks the strength rules (≥8 chars, one uppercase, one
// number, one special char) and returns the per-rule breakdown plus an overall
// verdict.
func ValidatePassword(password string) (PasswordRequirements, bool) {
	req := PasswordRequirements{
		MinLength:      len(password) >= 8,
		HasUppercase:   reUppercase.MatchString(password),
		HasNumber:      reNumber.MatchString(password),
		HasSpecialChar: reSpecial.MatchString(password),
	}
	valid := req.MinLength && req.HasUppercase && req.HasNumber && req.HasSpecialChar
	return req, valid
}
