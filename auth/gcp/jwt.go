package gcp

import (
	"context"
	"encoding/json"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
	"net/http"
	"strings"
)

const (
	prefix = "Bearer "
)

//TokenInfo extract token info, but it does not verify token
func TokenInfo(ctx context.Context, tokenString string, verify bool) (*oauth2.Tokeninfo, error) {
	if strings.HasPrefix(tokenString, prefix) {
		tokenString = tokenString[len(prefix):]
	}
	if verify {
		svc, err := oauth2.NewService(ctx, option.WithHTTPClient(http.DefaultClient))
		if err != nil {
			return nil, err
		}
		return svc.Tokeninfo().IdToken(tokenString).Context(ctx).Do()
	}
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//ignores token verification
		return nil, nil
	})
	jwtClaim := token.Claims
	err := jwtClaim.Valid()
	if err != nil {
		return nil, err
	}
	var result = &oauth2.Tokeninfo{}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok {
		data, _ := json.Marshal(claims)
		err = json.Unmarshal(data, result)
	}
	return result, err
}
