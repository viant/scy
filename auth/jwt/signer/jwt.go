package signer

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/viant/scy/cred"
)

// LoadJWTConfig loads and parses a service account JSON from disk.
func LoadJWTConfig(jsonPath string) (*cred.JwtConfig, error) {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, err
	}
	return ParseJWTConfig(data)
}

// ParseJWTConfig parses raw service account JSON bytes into ServiceAccount.
func ParseJWTConfig(jsonData []byte) (*cred.JwtConfig, error) {
	var cfg cred.JwtConfig
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		return nil, fmt.Errorf("parse service account json: %w", err)
	}
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		return nil, fmt.Errorf("parse service account json: %w", err)
	}
	if cfg.PrivateKey == "" {
		return nil, fmt.Errorf("private_key was empty in service account JSON")
	}
	return &cfg, nil
}
