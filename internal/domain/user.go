package domain

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// AuthProvider is how the user authenticates.
type AuthProvider string

const (
	// AuthProviderEmail — login with email + password.
	AuthProviderEmail AuthProvider = "email"
	// AuthProviderGoogle — login via Google OAuth.
	AuthProviderGoogle AuthProvider = "google"
)

// UserRole is the privileged system role used for authorization.
type UserRole string

const (
	// RoleUser — default role; a regular advertiser account.
	RoleUser UserRole = "user"
	// RoleAdmin — full administrative access.
	RoleAdmin UserRole = "admin"
	// RoleModerator — can review and moderate uploaded content.
	RoleModerator UserRole = "moderator"
)

// User holds the authentication and authorization state of a platform account.
// Mirrors the auth-related subset of the cannect-web Mongoose model
// (src/lib/db/models/User.ts).
type User struct {
	// ID is the MongoDB document identifier (_id).
	ID primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	// Email is the unique login identifier (stored lowercased/trimmed).
	Email string `bson:"email" json:"email"`

	// AuthProvider records which method the account authenticates with.
	AuthProvider AuthProvider `bson:"authProvider" json:"authProvider"`
	// PasswordHash is the bcrypt/argon hash of the password. Empty for
	// OAuth-only accounts. Never serialized to clients (mirrors toJSON strip).
	PasswordHash string `bson:"passwordHash,omitempty" json:"-"`
	// GoogleID is the Google account subject id; set for Google sign-in.
	GoogleID string `bson:"googleId,omitempty" json:"googleId,omitempty"`

	// Role drives authorization (access level across the app).
	Role UserRole `bson:"role" json:"role"`

	// TelegramID is the admin's linked Telegram account id, used as the second
	// factor for admin login (Telegram Login Widget). Empty until linked.
	TelegramID string `bson:"telegramId,omitempty" json:"telegramId,omitempty"`

	// EmailVerified is true once the user confirms ownership of their email.
	EmailVerified bool `bson:"emailVerified" json:"emailVerified"`
	// LastLogin is the timestamp of the most recent successful login.
	LastLogin time.Time `bson:"lastLogin,omitempty" json:"lastLogin,omitempty"`

	// VerificationCode is the one-time code sent to confirm the email.
	// Stored but never serialized to clients (mongoose select:false).
	VerificationCode string `bson:"verificationCode,omitempty" json:"-"`
	// VerificationCodeExpiry is when VerificationCode stops being valid.
	VerificationCodeExpiry time.Time `bson:"verificationCodeExpiry,omitempty" json:"-"`
	// PasswordResetCode is the one-time code issued for a password reset.
	PasswordResetCode string `bson:"passwordResetCode,omitempty" json:"-"`
	// PasswordResetCodeExpiry is when PasswordResetCode stops being valid.
	PasswordResetCodeExpiry time.Time `bson:"passwordResetCodeExpiry,omitempty" json:"-"`

	// CreatedAt is when the account was created (mongoose timestamps).
	CreatedAt time.Time `bson:"createdAt,omitempty" json:"createdAt,omitempty"`
	// UpdatedAt is when the account was last modified (mongoose timestamps).
	UpdatedAt time.Time `bson:"updatedAt,omitempty" json:"updatedAt,omitempty"`
}
