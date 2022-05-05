package jwt

import (
	"encoding/json"
	"fmt"
	jw "github.com/golang-jwt/jwt/v4"
)

type Claims struct {
	JwtID                string `json:"jti"`
	Issuer               string `json:"iss"`
	Subject              string `json:"sub"`
	Audience             string `json:"aud"`
	Expiration           int64  `json:"exp"`
	AccessTokenHashValue string `json:"at_hash"`
	AuthorizedParty      string `json:"azp"`
	Email                string `json:"email"`
	EmailVerified        bool   `json:"email_verified"`
	IssuedAt             int64  `json:"iat"`
}

func TokenClaims(token *jw.Token) (*Claims, error) {
	jwtClaim := token.Claims
	if err := jwtClaim.Valid(); err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jw.MapClaims)
	if !ok {
		return nil, fmt.Errorf("expected: %T, but had: %T", claims, token.Claims)
	}
	data, _ := json.Marshal(claims)
	ret := &Claims{}
	err := json.Unmarshal(data, ret)
	return ret, err
}
