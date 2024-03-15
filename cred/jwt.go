package cred

import (
	"fmt"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
	"io/ioutil"
)

// JwtConfig represents jws config
type JwtConfig struct {
	ClientEmail             string   `json:"client_email,omitempty"`
	TokenURL                string   `json:"token_url,omitempty"`
	PrivateKey              string   `json:"private_key,omitempty"`
	PrivateKeyID            string   `json:"private_key_id,omitempty"`
	ProjectID               string   `json:"project_id,omitempty"`
	TokenURI                string   `json:"token_uri,omitempty"`
	Type                    string   `json:"type,omitempty"`
	ClientX509CertURL       string   `json:"client_x509_cert_url,omitempty"`
	AuthProviderX509CertURL string   `json:"auth_provider_x509_cert_url,omitempty"`
	Scopes                  []string `json:",omitempty"`
}

// NewJWTConfig returns new JWT config for supplied scopes
func (c *Generic) NewJWTConfig(scopes ...string) (*jwt.Config, error) {
	var result = &jwt.Config{
		Email:        c.ClientEmail,
		Subject:      c.ClientEmail,
		PrivateKey:   []byte(c.PrivateKey),
		PrivateKeyID: c.PrivateKeyID,
		Scopes:       scopes,
		TokenURL:     c.TokenURL,
	}
	if c.PrivateKeyPath != "" && c.PrivateKey == "" {
		privateKey, err := ioutil.ReadFile(c.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open provide key: %v, %v", c.PrivateKeyPath, err)
		}
		result.PrivateKey = privateKey
	}
	if result.TokenURL == "" {
		result.TokenURL = google.JWTTokenURL
	}
	return result, nil
}
