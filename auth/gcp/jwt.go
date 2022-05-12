package gcp

import (
	"context"
	sjwt "github.com/viant/scy/auth/jwt"
	"strings"
)

const (
	certURL  = "https://www.googleapis.com/oauth2/v3/certs"
	authType = "Bearer "
)

var keys = sjwt.NewCache()

//JwtClaims extract token info, but it does not verify token
func JwtClaims(ctx context.Context, tokenString string) (*sjwt.Claims, error) {
	if strings.HasPrefix(tokenString, authType) {
		tokenString = tokenString[len(authType):]
	}
	token, err := sjwt.VerifyToken(ctx, tokenString, certURL, keys)
	if err != nil {
		return nil, err
	}
	return sjwt.NewClaim(token)
}
