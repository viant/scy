package jwt

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"strconv"
	"strings"
	"time"
)

type TokenOption func(*jwt.Token)

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
	Nonce         string      `json:"nonce,omitempty"`
	AtHash        string      `json:"at_hash,omitempty"`
	Data          interface{} `json:"dat,omitempty"`
	jwt.RegisteredClaims
}

func (c *Claims) UnmarshalJSON(data []byte) error {
	type claimsJSON struct {
		Email         string          `json:"email,omitempty"`
		Username      string          `json:"username,omitempty"`
		FirstName     string          `json:"first_name,omitempty"`
		LastName      string          `json:"last_name,omitempty"`
		AccountName   string          `json:"account_name,omitempty"`
		AccountId     int             `json:"account_id,omitempty"`
		Scope         string          `json:"scope,omitempty"`
		Cognito       string          `json:"cognito,omitempty"`
		VerifiedEmail bool            `json:"verified_email,omitempty"`
		Nonce         string          `json:"nonce,omitempty"`
		AtHash        string          `json:"at_hash,omitempty"`
		Data          interface{}     `json:"dat,omitempty"`
		UserIDRaw     json.RawMessage `json:"user_id,omitempty"`
		UIDRaw        json.RawMessage `json:"uid,omitempty"`
		jwt.RegisteredClaims
	}
	aux := &claimsJSON{}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	c.Email = aux.Email
	c.Username = aux.Username
	c.FirstName = aux.FirstName
	c.LastName = aux.LastName
	c.AccountName = aux.AccountName
	c.AccountId = aux.AccountId
	c.Scope = aux.Scope
	c.Cognito = aux.Cognito
	c.VerifiedEmail = aux.VerifiedEmail
	c.Nonce = aux.Nonce
	c.AtHash = aux.AtHash
	c.Data = aux.Data
	c.RegisteredClaims = aux.RegisteredClaims
	c.UserID = 0
	if id, ok := parseFlexibleIntRaw(aux.UserIDRaw); ok {
		c.UserID = id
		return nil
	}
	if id, ok := parseFlexibleIntRaw(aux.UIDRaw); ok {
		c.UserID = id
	}
	return nil
}

func (c *Claims) VerifyExpiresAt(cmp time.Time, req bool) bool {
	if c.ExpiresAt == nil {
		return verifyExp(nil, cmp, req)
	}

	return verifyExp(&c.ExpiresAt.Time, cmp, req)
}

func verifyExp(exp *time.Time, now time.Time, required bool) bool {
	if exp == nil {
		return !required
	}
	return now.Before(*exp)
}

func (c *Claims) VerifyAudience(cmp string, req bool) bool {
	return verifyAud(c.Audience, cmp, req)
}

func verifyAud(aud []string, cmp string, required bool) bool {
	if len(aud) == 0 {
		return !required
	}
	// use a var here to keep constant time compare when looping over a number of claims
	result := false

	var stringClaims string
	for _, a := range aud {
		if subtle.ConstantTimeCompare([]byte(a), []byte(cmp)) != 0 {
			result = true
		}
		stringClaims = stringClaims + a
	}

	// case where "" is sent in one or many aud claims
	if len(stringClaims) == 0 {
		return !required
	}

	return result
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

func parseFlexibleIntRaw(raw json.RawMessage) (int, bool) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return 0, false
	}
	var asInt int
	if err := json.Unmarshal(raw, &asInt); err == nil {
		return asInt, true
	}
	var asInt64 int64
	if err := json.Unmarshal(raw, &asInt64); err == nil {
		return int(asInt64), true
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		asString = strings.TrimSpace(asString)
		if asString == "" {
			return 0, false
		}
		if parsed, err := strconv.Atoi(asString); err == nil {
			return parsed, true
		}
	}
	return 0, false
}
