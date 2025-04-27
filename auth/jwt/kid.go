package jwt

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
)

// GenerateKid generates a Key ID (kid) from the given RSA public key.
func GenerateKid(pub *rsa.PublicKey) (string, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(derBytes)
	kid := base64.RawURLEncoding.EncodeToString(sum[:8]) // shorten to 8 bytes for readability
	return kid, nil
}
