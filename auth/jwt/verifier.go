package jwt

import (
	"context"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
)

func VerifyToken(ctx context.Context, tokenString string, certURL string, cache *Cache) (*jwt.Token, error) {
	keySet, err := cache.Fetch(ctx, certURL)
	if err != nil {
		return nil, err
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("kid header not found")
		}
		keys, ok := keySet.LookupKeyID(kid)
		if !ok {
			return nil, fmt.Errorf("key %v not found", kid)
		}
		var publicKey interface{}
		err = keys.Raw(&publicKey)
		if err != nil {
			return nil, fmt.Errorf("could not parse pubkey")
		}
		return publicKey, nil
	})
	return token, err
}
