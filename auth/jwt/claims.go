package jwt

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
)

//Claims represents JWT claim
type Claims struct {
	Email         string      `json:"email,omitempty"`
	UserID        int         `json:"uid,omitempty"`
	FirstName     string      `json:"fname,omitempty"`
	LastName      string      `json:"lname,omitempty"`
	AccountName   string      `json:"acct,omitempty"`
	AccountId     int         `json:"acctid,omitempty"`
	Scope         string      `json:"scope,omitempty"`
	Cognito       string      `json:"cognito,omitempty"`
	VerifiedEmail bool        `json:"verified_email,omitempty"`
	Data          interface{} `json:"dat,omitempty"`
	jwt.RegisteredClaims
}

//NewClaim returns jwt claim from token
func NewClaim(token *jwt.Token) (*Claims, error) {
	var result = &Claims{}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("expected; %T, but had: %T", claims, token.Claims)
	}
	data, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, result)
	return result, err
}
