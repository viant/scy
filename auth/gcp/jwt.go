package gcp

import (
	"context"
	sjwt "github.com/viant/scy/auth/jwt"
	"github.com/viant/scy/auth/jwt/verifier"
	"strings"
)

const (
	certURL  = "https://www.googleapis.com/oauth2/v3/certs"
	authType = "Bearer "
)

var verifierService = verifier.New(&verifier.Config{CertURL: certURL})

//JwtClaims extract token info, but it does not verify token
func JwtClaims(ctx context.Context, tokenString string) (*sjwt.Claims, error) {
	if strings.HasPrefix(tokenString, authType) {
		tokenString = tokenString[len(authType):]
	}
	token, err := verifierService.Validate(ctx, tokenString)
	if err != nil {
		return nil, err
	}
	return sjwt.NewClaim(token)
}
