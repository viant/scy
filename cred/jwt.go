package cred

import (
	"golang.org/x/oauth2/jwt"
)

//JwtConfig represents jws config
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
	jwtClientConfig         *jwt.Config
}
