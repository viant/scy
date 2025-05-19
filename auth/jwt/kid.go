package jwt

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
)

// GenerateKid returns a JWK SHA-256 thumbprint in
// base64url-without-padding – exactly what AssignKeyID
// expects if you pass crypto.SHA256.
func GenerateKid(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	out := sum[:]
	out = out[:8]
	return base64.RawURLEncoding.EncodeToString(out), nil
}
