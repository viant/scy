package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/viant/scy/auth/authorizer"
	"golang.org/x/oauth2"
	"strings"
)

// AuthorizeCmd command for authorization
type AuthorizeCmd struct {
	AuthFlow   string   `short:"a" long:"authFlow" description:"authentication flow (Browser or OOB)" choice:"OOB" choice:"Browser" `
	ConfigURL  string   `short:"c" long:"configURL" description:"OAuth2 config URL"`
	SecretsURL string   `short:"e" long:"secretsURL" description:"secrets URL for username/password"`
	Scopes     []string `short:"s" long:"scopes" description:"OAuth2 scopes"`
	UsePKCE    bool     `short:"p" long:"usePKCE" description:"use PKCE for OAuth2 flow"`
	TokenType  string   `long:"tokenType" description:"output token type" choice:"id" choice:"access" choice:"json"`
	Key        string   `short:"k" long:"key" description:"key i.e blowfish://default"`
}

// Init normalizes file locations
func (a *AuthorizeCmd) Init() {
	a.ConfigURL = normalizeLocation(a.ConfigURL)
	a.SecretsURL = normalizeLocation(a.SecretsURL)
}

// Validate validates the authorize command options
func (a *AuthorizeCmd) Validate() error {
	return nil
}

// Execute runs the authorize command
func (a *AuthorizeCmd) Execute(args []string) error {
	a.Init()
	if err := a.Validate(); err != nil {
		return err
	}
	return Authorize(a)
}

// Authorize handles authorization
func Authorize(auth *AuthorizeCmd) error {
	service := authorizer.New()

	if auth.Key != "" {
		auth.ConfigURL += "|" + auth.Key
		auth.SecretsURL += "|" + auth.Key

	}

	command := &authorizer.Command{
		AuthFlow: auth.AuthFlow,
		OAuthConfig: authorizer.OAuthConfig{
			ConfigURL: auth.ConfigURL,
		},
		SecretsURL: auth.SecretsURL,
		Scopes:     auth.Scopes,
		UsePKCE:    auth.UsePKCE,
	}

	token, err := service.Authorize(context.Background(), command)
	if err != nil {
		return fmt.Errorf("authorization failed: %v", err)
	}

	output, err := formatAuthorizeOutput(token, auth.TokenType)
	if err != nil {
		return err
	}
	fmt.Println(output)

	return nil
}

func formatAuthorizeOutput(token *oauth2.Token, tokenType string) (string, error) {
	if token == nil {
		return "", fmt.Errorf("oauth token was nil")
	}
	switch tokenType {
	case "id":
		idToken, ok := token.Extra("id_token").(string)
		if !ok || idToken == "" {
			return "", fmt.Errorf("id token was not present in oauth response")
		}
		return idToken, nil
	case "access":
		if token.AccessToken == "" {
			return "", fmt.Errorf("access token was empty")
		}
		return token.AccessToken, nil
	case "json":
		data, err := json.MarshalIndent(token, "", "  ")
		if err != nil {
			return "", fmt.Errorf("failed to marshal token: %v", err)
		}
		return string(data), nil
	case "":
		data, err := json.MarshalIndent(token, "", "  ")
		if err != nil {
			return "", fmt.Errorf("failed to marshal token: %v", err)
		}
		var lines = []string{string(data)}
		if token.AccessToken != "" {
			lines = append(lines, "Access Token: "+token.AccessToken)
		}
		if idToken, _ := token.Extra("id_token").(string); idToken != "" {
			lines = append(lines, "ID Token: "+idToken)
		}
		if token.RefreshToken != "" {
			lines = append(lines, "Refresh Token: "+token.RefreshToken)
		}
		return strings.Join(lines, "\n\n"), nil
	default:
		return "", fmt.Errorf("unsupported token type: %s", tokenType)
	}
}
