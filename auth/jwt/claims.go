package jwt

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
)

// Claims represents JWT claim
type Claims struct {
	Email         string      `json:"email,omitempty"`
	UserID        int         `json:"user_id,omitempty"`
	Username      string      `json:"username,omitempty"`
	FirstName     string      `json:"first_name,omitempty"`
	LastName      string      `json:"last_name,omitempty"`
	AccountName   string      `json:"account_name,omitempty"`
	AccountId     int         `json:"account_id,omitempty"`
	Scope         string      `json:"scope,omitempty"`
	Cognito       string      `json:"cognito,omitempty"`
	VerifiedEmail bool        `json:"verified_email,omitempty"`
	Type          string      `json:"typ,omitempty"`
	Data          interface{} `json:"dat,omitempty"`
	jwt.RegisteredClaims
}

// NewClaim returns jwt claim from token
func NewClaim(token *jwt.Token) (*Claims, error) {
	var result = &Claims{}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("expected; %T, but had: %T", claims, token.Claims)
	}
	//expand claims
	if value, ok := claims["dat"]; ok {
		var dataMap map[string]interface{}
		if rawData, ok := value.(string); ok {
			if err := json.Unmarshal([]byte(rawData), &dataMap); err == nil {
				for k, v := range dataMap {
					if _, ok = claims[k]; ok {
						continue
					}
					claims[k] = v
				}
			}
		}
	}
	data, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, result)
	return result, err
}
