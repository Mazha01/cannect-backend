package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestOIDC(t *testing.T, key *rsa.PrivateKey, kid string) *OIDC {
	t.Helper()
	return &OIDC{
		cfg:         OIDCConfig{Issuer: "https://issuer.test", ClientID: "client-123"},
		http:        &http.Client{Timeout: time.Second},
		disc:        &oidcDiscovery{Issuer: "https://issuer.test"},
		keys:        map[string]*rsa.PublicKey{kid: &key.PublicKey},
		keysFetched: time.Now(),
	}
}

func signIDToken(t *testing.T, key *rsa.PrivateKey, kid string, claims oidcClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func baseClaims() oidcClaims {
	return oidcClaims{
		Nonce:    "nonce-1",
		Name:     "Ada Lovelace",
		Username: "ada",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://issuer.test",
			Subject:   "777",
			Audience:  jwt.ClaimStrings{"client-123"},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
}

func TestVerifyIDToken_Valid(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	o := newTestOIDC(t, key, "k1")
	token := signIDToken(t, key, "k1", baseClaims())

	id, err := o.verifyIDToken(context.Background(), o.disc, token, "nonce-1")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.Subject != "777" || id.Username != "ada" || id.Name != "Ada Lovelace" {
		t.Fatalf("unexpected identity: %+v", id)
	}
}

func TestVerifyIDToken_NonceMismatch(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	o := newTestOIDC(t, key, "k1")
	token := signIDToken(t, key, "k1", baseClaims())

	if _, err := o.verifyIDToken(context.Background(), o.disc, token, "wrong-nonce"); err == nil {
		t.Fatal("nonce mismatch was accepted")
	}
}

func TestVerifyIDToken_WrongAudience(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	o := newTestOIDC(t, key, "k1")
	c := baseClaims()
	c.Audience = jwt.ClaimStrings{"someone-else"}
	token := signIDToken(t, key, "k1", c)

	if _, err := o.verifyIDToken(context.Background(), o.disc, token, "nonce-1"); err == nil {
		t.Fatal("token for wrong audience was accepted")
	}
}

func TestVerifyIDToken_WrongKeyRejected(t *testing.T) {
	signing, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	o := newTestOIDC(t, other, "k1") // JWKS holds a different key than the signer
	token := signIDToken(t, signing, "k1", baseClaims())

	if _, err := o.verifyIDToken(context.Background(), o.disc, token, "nonce-1"); err == nil {
		t.Fatal("token signed by an unknown key was accepted")
	}
}

func TestRSAPublicKeyFromJWK_RoundTrip(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	nB64 := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
	eB64 := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())

	pub, err := rsaPublicKeyFromJWK(nB64, eB64)
	if err != nil {
		t.Fatalf("parse jwk: %v", err)
	}
	if pub.N.Cmp(key.PublicKey.N) != 0 || pub.E != key.PublicKey.E {
		t.Fatal("round-tripped key does not match")
	}
}

func TestNewPKCE(t *testing.T) {
	verifier, challenge, err := NewPKCE()
	if err != nil {
		t.Fatalf("pkce: %v", err)
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != want {
		t.Fatalf("challenge != S256(verifier): %q vs %q", challenge, want)
	}
}
