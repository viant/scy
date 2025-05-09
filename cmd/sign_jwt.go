package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/viant/afs"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/jwt/signer"
	"time"
)

// SignJwtCmd command for signing JWT tokens
type SignJwtCmd struct {
	TypedSource
	RSAKey    string `short:"r" long:"rsa" description:"private/public key location"`
	HMacKey   string `short:"a" long:"hmac" description:"hmac key location (base64 encoded)"`
	ExpirySec int    `short:"e" long:"expiry" description:"expiry TTL in sec"`
	Key       string `short:"k" long:"key" description:"key i.e blowfish://default"`
}

// Init normalizes file locations
func (s *SignJwtCmd) Init() {
	s.SourceURL = normalizeLocation(s.SourceURL)
	s.RSAKey = normalizeLocation(s.RSAKey)
	s.HMacKey = normalizeLocation(s.HMacKey)
}

// Validate validates the signJwt command options
func (s *SignJwtCmd) Validate() error {


	if s.RSAKey == "" && s.HMacKey == "" {
		return fmt.Errorf("RSAKey/HMacKey were empty")
	}
	if s.SourceURL == "" {
		return fmt.Errorf("src was empty")
	}
	return nil
}

// Execute runs the signJwt command
func (s *SignJwtCmd) Execute(args []string) error {
	s.Init()
	return SignJwtClaim(s)
}

// SignJwtClaim signs JWT claims
func SignJwtClaim(sign *SignJwtCmd) error {


	cfg := &signer.Config{}
	if sign.HMacKey != "" {
		cfg.HMAC = &scy.Resource{
			URL: sign.HMacKey,
			Key: sign.Key,
		}
	} else if sign.RSAKey != "" {
		cfg.RSA = &scy.Resource{
			URL: sign.RSAKey,
			Key: sign.Key,
		}
	}
	jwtSigner := signer.New(cfg)
	if err := jwtSigner.Init(context.Background()); err != nil {
		return err
	}
	fs := afs.New()
	var content = map[string]interface{}{}
	data, err := fs.DownloadWithURL(context.Background(), sign.SourceURL)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(data, &content); err != nil {
		return fmt.Errorf("invalid JSON content: %v", err)
	}
	expiry := time.Duration(sign.ExpirySec) * time.Second
	if expiry == 0 {
		expiry = time.Hour
	}
	token, err := jwtSigner.Create(expiry, content)
	if err != nil {
		return err
	}
	fmt.Printf("JWT TOKEN: %s\n", token)
	return nil
}
