package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	sjwt "github.com/viant/scy/auth/jwt"
	"github.com/viant/scy/auth/jwt/verifier"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	certURL      = "https://www.googleapis.com/oauth2/v3/certs"
	tokenInfoURL = "https://oauth2.googleapis.com/tokeninfo"
	userInfoURL  = "https://www.googleapis.com/oauth2/v2/userinfo"
	authType     = "Bearer "
)

var verifierService = verifier.New(&verifier.Config{CertURL: certURL})

// JwtClaims extract token info, but it does not verify token
func JwtClaims(ctx context.Context, tokenString string) (*sjwt.Claims, error) {
	if strings.HasPrefix(tokenString, authType) {
		tokenString = tokenString[len(authType):]
	}

	token, err := verifierService.Validate(ctx, tokenString)
	if err != nil {
		if claims, aErr := validateAccessToken(ctx, tokenString); aErr == nil {
			return claims, nil
		}
		return nil, err
	}
	claims, err := sjwt.NewClaim(token)
	return claims, err
}

const (
	verifiedEmailKey = "email_verified"
)

func validateAccessToken(ctx context.Context, accessTokenString string) (*sjwt.Claims, error) {
	data, err := fetchInfo(ctx, tokenInfoURL, accessTokenString)
	if err != nil {
		return nil, err
	}

	claims := &sjwt.Claims{}
	if err := json.Unmarshal(data, claims); err != nil {
		return nil, err
	}
	aMap := map[string]interface{}{}
	if err = json.Unmarshal(data, &aMap); err == nil {
		if value, ok := aMap[verifiedEmailKey]; ok && value == "true" {
			claims.VerifiedEmail = true
		}
	}
	if claims.VerifyExpiresAt(time.Now(), true) {
		updateClaimsWithProfileInfo(ctx, accessTokenString, claims)
	}
	return claims, nil
}

const (
	firstNameKey = "given_name"
	lastNameKey  = "family_name"
	nameKey      = "name"
	idKey        = "id"
)

func updateClaimsWithProfileInfo(ctx context.Context, accessTokenString string, claims *sjwt.Claims) {
	if strings.Contains(claims.Scope, "userinfo.email") {
		if data, err := fetchInfo(ctx, userInfoURL, accessTokenString); err == nil {
			aMap := map[string]interface{}{}
			if err = json.Unmarshal(data, &aMap); err == nil {
				if value, ok := aMap[firstNameKey]; ok {
					claims.FirstName = value.(string)
				}
				if value, ok := aMap[lastNameKey]; ok {
					claims.LastName = value.(string)
				}
				if value, ok := aMap[nameKey]; ok {
					claims.Username = value.(string)
				}
				if value, ok := aMap[idKey]; ok {
					idLiteral := value.(string)
					id, _ := strconv.Atoi(idLiteral)
					claims.UserID = id
				}
			}
		}
	}
}

func fetchInfo(ctx context.Context, URL, tokenString string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, "GET", URL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", authType+tokenString)
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.Body == nil {
		return nil, fmt.Errorf("body was empty")
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	return data, nil
}
