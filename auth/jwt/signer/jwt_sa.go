package signer

import (
	"context"
	"os"
	"time"
)

// NewSignerFromServiceAccountJSON initializes an RSA JWT signer from a Service Account JSON file.
// It returns the signer and the account email for convenience.
func NewSignerFromServiceAccountJSON(ctx context.Context, jsonPath string) (*Service, string, error) {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, "", err
	}
	return NewSignerFromServiceAccountBytes(ctx, data)
}

// NewSignerFromServiceAccountBytes initializes an RSA JWT signer from raw Service Account JSON bytes.
// It returns the signer and the account email for convenience.
func NewSignerFromServiceAccountBytes(ctx context.Context, jsonData []byte) (*Service, string, error) {
	sa, err := ParseJWTConfig(jsonData)
	if err != nil {
		return nil, "", err
	}
	signer, err := NewFromPEMKey(ctx, []byte(sa.PrivateKey))
	if err != nil {
		return nil, "", err
	}
	return signer, sa.ClientEmail, nil
}

// CreateJWT signs arbitrary claims with optional scope and TTL using the provided signer.
func CreateJWT(signer *Service, ttl time.Duration, content any, scope ...string) (string, error) {
	var payload any = content
	if len(scope) > 0 && scope[0] != "" {
		switch v := content.(type) {
		case map[string]any:
			clone := make(map[string]any, len(v)+1)
			for k, val := range v {
				clone[k] = val
			}
			if _, exists := clone["scope"]; !exists {
				clone["scope"] = scope[0]
			}
			payload = clone
		case nil:
			payload = map[string]any{"scope": scope[0]}
		default:
			payload = map[string]any{
				"scope": scope[0],
				"dat":   v,
			}
		}
	}
	return signer.Create(ttl, payload)
}
