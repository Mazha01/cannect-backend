package auth

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
)

// googleEndpoint is Google's OAuth 2.0 endpoint, inlined to avoid importing
// golang.org/x/oauth2/google (which pulls the cloud metadata client).
var googleEndpoint = oauth2.Endpoint{
	AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
	TokenURL: "https://oauth2.googleapis.com/token",
}

// GoogleConfig holds the OAuth client credentials and redirect URL.
type GoogleConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// GoogleUser is the verified identity returned by Google.
type GoogleUser struct {
	Sub           string // Google account id
	Email         string
	Name          string
	Picture       string
	EmailVerified bool
}

// Google performs the Google OAuth code flow and ID-token verification.
type Google struct {
	clientID string
	oauth    *oauth2.Config
}

// NewGoogle builds a Google authenticator. It is "enabled" only when both the
// client id and secret are set.
func NewGoogle(cfg GoogleConfig) *Google {
	return &Google{
		clientID: cfg.ClientID,
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     googleEndpoint,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
		},
	}
}

// Enabled reports whether Google sign-in is configured.
func (g *Google) Enabled() bool {
	return g.clientID != "" && g.oauth.ClientSecret != ""
}

// AuthCodeURL builds the Google consent-screen URL to redirect the browser to.
func (g *Google) AuthCodeURL(state string) string {
	return g.oauth.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
}

// Exchange swaps an authorization code for tokens and returns the verified user
// from the id_token (browser callback flow).
func (g *Google) Exchange(ctx context.Context, code string) (*GoogleUser, error) {
	tok, err := g.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return nil, fmt.Errorf("no id_token in google response")
	}
	return g.VerifyIDToken(ctx, rawID)
}

// VerifyIDToken validates a Google ID token (mobile / one-tap flow) against our
// client id and returns the verified user.
func (g *Google) VerifyIDToken(ctx context.Context, idToken string) (*GoogleUser, error) {
	payload, err := idtoken.Validate(ctx, idToken, g.clientID)
	if err != nil {
		return nil, fmt.Errorf("validate id_token: %w", err)
	}
	return &GoogleUser{
		Sub:           payload.Subject,
		Email:         claimString(payload.Claims, "email"),
		Name:          claimString(payload.Claims, "name"),
		Picture:       claimString(payload.Claims, "picture"),
		EmailVerified: claimBool(payload.Claims, "email_verified"),
	}, nil
}

func claimString(claims map[string]interface{}, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

func claimBool(claims map[string]interface{}, key string) bool {
	if v, ok := claims[key].(bool); ok {
		return v
	}
	return false
}
