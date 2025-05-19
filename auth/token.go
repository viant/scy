package auth

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"time"
)

type Token struct {
	oauth2.Token
	IDToken string `json:"id_token,omitempty"`
}

// Expired returns true if expired
func (t Token) Expired(now time.Time) bool {
	return t.Expiry.Before(now)
}

func (t *Token) IdentityToken() (*oauth2.Token, error) {
	if t.IDToken == "" {
		return nil, fmt.Errorf("invalid identity token")
	}
	return &oauth2.Token{
		AccessToken:  t.IDToken,
		TokenType:    t.TokenType,
		RefreshToken: t.RefreshToken,
		Expiry:       t.Expiry,
	}, nil
}

func (t *Token) PopulateIDToken() {
	raw := t.Extra("id_token")
	if raw == nil {
		return
	}
	t.IDToken, _ = raw.(string)
}

// IdToken returns the id token from the oauth2 token
func IdToken(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error) {
	idTokenString := ""
	if value := token.Extra("id_token"); value != nil {
		idTokenString, _ = value.(string)
	}
	if idTokenString == "" {
		return nil, fmt.Errorf("failed to get identity token")
	}
	var unverifiedToken *jwt.Token
	_, err := jwt.Parse(idTokenString, func(token *jwt.Token) (interface{}, error) {
		unverifiedToken = token
		return nil, fmt.Errorf("unverified token")
	})
	if unverifiedToken == nil && err != nil {
		return nil, fmt.Errorf("failed to parse id token: %w", err)
	}
	expiryTime, err := unverifiedToken.Claims.GetExpirationTime()
	if err != nil {
		return nil, fmt.Errorf("failed to get expiration time: %w", err)
	}
	return &oauth2.Token{
		TokenType:    "Bearer",
		AccessToken:  idTokenString,
		RefreshToken: token.RefreshToken,
		Expiry:       expiryTime.Add(0),
	}, nil

}
