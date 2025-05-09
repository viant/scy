package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/viant/afs"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/gcp"
	"github.com/viant/scy/auth/gcp/client"
	"github.com/viant/scy/auth/jwt/verifier"
)


// VerifyJwtCmd command for verifying JWT tokens
type VerifyJwtCmd struct {
	TypedSource
	RSAKey    string `short:"r" long:"rsa" description:"private/public key location"`
	HMacKey   string `short:"a" long:"hmac" description:"hmac key location (base64 encoded)"`
	Firebase  bool   `short:"f" long:"firebase" description:"firebase"`
	Key       string `short:"k" long:"key" description:"key i.e blowfish://default"`
	ProjectId string `short:"p" long:"projectId" description:"project id"`
}

// Init normalizes file locations
func (v *VerifyJwtCmd) Init() {
	v.SourceURL = normalizeLocation(v.SourceURL)
	v.RSAKey = normalizeLocation(v.RSAKey)
	v.HMacKey = normalizeLocation(v.HMacKey)
}

// Validate validates the verifyJwt command options
func (v *VerifyJwtCmd) Validate() error {
	if !v.Firebase && v.RSAKey == "" && v.HMacKey == "" {
		return fmt.Errorf("RSAKey/HMacKey was empty")
	}
	if v.SourceURL == "" {
		return fmt.Errorf("src was empty")
	}
	return nil
}

// Execute runs the verifyJwt command
func (v *VerifyJwtCmd) Execute(args []string) error {
	v.Init()
	return VerifyJwtClaim(v)
}




// VerifyJwtClaim verifies JWT claims
func VerifyJwtClaim(verify *VerifyJwtCmd) error {
	if verify.Firebase {
		return VerifyFirebaseJwtClaim(context.Background(), verify)
	}
	jwtVerifier := verifier.New(&verifier.Config{RSA: []*scy.Resource{{URL: verify.RSAKey,
		Key: verify.Key,
	}}, HMAC: &scy.Resource{
		URL: verify.HMacKey,
		Key: verify.Key,
	}})

	if err := jwtVerifier.Init(context.Background()); err != nil {
		return err
	}
	fs := afs.New()
	jwtTokenString, err := fs.DownloadWithURL(context.Background(), verify.SourceURL)
	if err != nil {
		return err
	}
	jwtClaim, err := jwtVerifier.VerifyClaims(context.Background(), string(jwtTokenString))
	if err != nil {
		return err
	}
	data, _ := json.Marshal(jwtClaim)
	fmt.Printf("JWT CLAIM: %s\n", data)
	return nil
}

// VerifyFirebaseJwtClaim verifies Firebase JWT claims
func VerifyFirebaseJwtClaim(ctx context.Context, verify *VerifyJwtCmd) error {
	gcpService := gcp.New(client.NewScy())
	identity, err := newFirebaseAuthorizer(ctx, verify, gcpService)
	if err != nil {
		return fmt.Errorf("failed to create firebase auth service: %w", err)
	}
	fs := afs.New()
	jwtTokenString, err := fs.DownloadWithURL(ctx, verify.SourceURL)
	if err != nil {
		return fmt.Errorf("invalid token source, %w", err)
	}

	jwtClaim, err := identity.VerifyIdentity(ctx, string(jwtTokenString))
	if err != nil {
		return err
	}
	data, _ := json.Marshal(jwtClaim)
	fmt.Printf("JWT CLAIM: %s\n", data)
	return nil
}
