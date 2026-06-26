package auth

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// GenerateVerificationCode returns a random 6-digit numeric code (100000-999999),
// matching the web generator (Math.floor(100000 + rand*900000)).
func GenerateVerificationCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()+100000), nil
}
