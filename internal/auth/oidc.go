package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OIDCConfig holds the OpenID Connect client settings. Issuer is the provider
// base URL (e.g. https://oauth.telegram.org); endpoints are discovered from
// `${Issuer}/.well-known/openid-configuration`.
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string

	// Explicit endpoints. When all three are set they are used directly and
	// discovery (`/.well-known/openid-configuration`) is skipped — needed for
	// providers (like Telegram) that may not publish a discovery document.
	AuthURL  string
	TokenURL string
	JWKSURI  string
}

// OIDCIdentity is the verified subject extracted from an id_token.
type OIDCIdentity struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Username      string
}

// OIDC is a minimal, dependency-light OpenID Connect Authorization-Code client
// with PKCE. It discovers endpoints, fetches and caches the provider JWKS, and
// verifies the RS256-signed id_token (issuer, audience, expiry, nonce).
type OIDC struct {
	cfg  OIDCConfig
	http *http.Client

	mu          sync.Mutex
	disc        *oidcDiscovery
	keys        map[string]*rsa.PublicKey
	keysFetched time.Time
}

type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// NewOIDC builds an OIDC client. Scopes default to "openid profile".
func NewOIDC(cfg OIDCConfig) *OIDC {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile"}
	}
	o := &OIDC{
		cfg:  cfg,
		http: &http.Client{Timeout: 15 * time.Second},
	}
	// Skip discovery when endpoints are provided explicitly.
	if cfg.AuthURL != "" && cfg.TokenURL != "" && cfg.JWKSURI != "" {
		o.disc = &oidcDiscovery{
			Issuer:                cfg.Issuer,
			AuthorizationEndpoint: cfg.AuthURL,
			TokenEndpoint:         cfg.TokenURL,
			JWKSURI:               cfg.JWKSURI,
		}
	}
	return o
}

// Enabled reports whether the OIDC client is configured.
func (o *OIDC) Enabled() bool {
	return o.cfg.Issuer != "" && o.cfg.ClientID != "" && o.cfg.ClientSecret != ""
}

// AuthCodeURL builds the authorization-request URL. state and nonce are CSRF /
// replay guards; challenge is the S256 PKCE code challenge.
func (o *OIDC) AuthCodeURL(ctx context.Context, state, nonce, challenge string) (string, error) {
	disc, err := o.discover(ctx)
	if err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", o.cfg.ClientID)
	q.Set("redirect_uri", o.cfg.RedirectURL)
	q.Set("scope", strings.Join(o.cfg.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	sep := "?"
	if strings.Contains(disc.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return disc.AuthorizationEndpoint + sep + q.Encode(), nil
}

// Exchange swaps an authorization code for tokens, verifies the id_token and
// returns the identity. codeVerifier is the PKCE verifier; expectedNonce is the
// nonce sent in AuthCodeURL.
func (o *OIDC) Exchange(ctx context.Context, code, codeVerifier, expectedNonce string) (*OIDCIdentity, error) {
	disc, err := o.discover(ctx)
	if err != nil {
		return nil, err
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", o.cfg.RedirectURL)
	form.Set("code_verifier", codeVerifier)
	form.Set("client_id", o.cfg.ClientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, disc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(o.cfg.ClientID), url.QueryEscape(o.cfg.ClientSecret))

	resp, err := o.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint status %d: %s", resp.StatusCode, string(body))
	}

	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if tok.IDToken == "" {
		return nil, fmt.Errorf("no id_token in token response")
	}
	return o.verifyIDToken(ctx, disc, tok.IDToken, expectedNonce)
}

type oidcClaims struct {
	Nonce         string `json:"nonce"`
	Name          string `json:"name"`
	Username      string `json:"preferred_username"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	jwt.RegisteredClaims
}

func (o *OIDC) verifyIDToken(ctx context.Context, disc *oidcDiscovery, idToken, expectedNonce string) (*OIDCIdentity, error) {
	claims := &oidcClaims{}
	_, err := jwt.ParseWithClaims(idToken, claims, o.keyfunc(ctx),
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(disc.Issuer),
		jwt.WithAudience(o.cfg.ClientID),
	)
	if err != nil {
		return nil, fmt.Errorf("verify id_token: %w", err)
	}
	if expectedNonce != "" && claims.Nonce != expectedNonce {
		return nil, fmt.Errorf("id_token nonce mismatch")
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("id_token missing subject")
	}
	return &OIDCIdentity{
		Subject:       claims.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          claims.Name,
		Username:      claims.Username,
	}, nil
}

// keyfunc resolves the RSA public key for a token's `kid`, refreshing the JWKS
// once if the key isn't cached (handles key rotation).
func (o *OIDC) keyfunc(ctx context.Context) jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		key, err := o.publicKey(ctx, kid, false)
		if err != nil {
			return nil, err
		}
		if key == nil {
			if key, err = o.publicKey(ctx, kid, true); err != nil {
				return nil, err
			}
		}
		if key == nil {
			return nil, fmt.Errorf("no JWKS key for kid %q", kid)
		}
		return key, nil
	}
}

func (o *OIDC) publicKey(ctx context.Context, kid string, forceRefresh bool) (*rsa.PublicKey, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if forceRefresh || o.keys == nil || time.Since(o.keysFetched) > time.Hour {
		if err := o.refreshKeysLocked(ctx); err != nil {
			return nil, err
		}
	}
	return o.keys[kid], nil
}

func (o *OIDC) refreshKeysLocked(ctx context.Context) error {
	disc := o.disc
	if disc == nil {
		var err error
		disc, err = o.discoverLocked(ctx)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, disc.JWKSURI, nil)
	if err != nil {
		return err
	}
	resp, err := o.http.Do(req)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := rsaPublicKeyFromJWK(k.N, k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	o.keys = keys
	o.keysFetched = time.Now()
	return nil
}

// rsaPublicKeyFromJWK builds an RSA public key from base64url modulus/exponent.
func rsaPublicKeyFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(nB64, "="))
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(eB64, "="))
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e == 0 {
		return nil, fmt.Errorf("invalid exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

func (o *OIDC) discover(ctx context.Context) (*oidcDiscovery, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.discoverLocked(ctx)
}

func (o *OIDC) discoverLocked(ctx context.Context) (*oidcDiscovery, error) {
	if o.disc != nil {
		return o.disc, nil
	}
	endpoint := strings.TrimRight(o.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := o.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc discovery status %d", resp.StatusCode)
	}
	var disc oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		return nil, fmt.Errorf("decode discovery: %w", err)
	}
	if disc.AuthorizationEndpoint == "" || disc.TokenEndpoint == "" || disc.JWKSURI == "" {
		return nil, fmt.Errorf("incomplete oidc discovery document")
	}
	o.disc = &disc
	return o.disc, nil
}

// NewPKCE returns a fresh PKCE (verifier, S256 challenge) pair.
func NewPKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// RandomURLToken returns a random URL-safe token for state/nonce values.
func RandomURLToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
