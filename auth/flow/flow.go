package flow

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"golang.org/x/oauth2"
	"strings"
)

// GenerateCodeChallenge creates a PKCE code challenge from a code verifier
func GenerateCodeChallenge(verifier string) string {
	sha := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sha[:])
}

// GenerateCodeVerifier creates a random code verifier for PKCE
func GenerateCodeVerifier() string {
	return randomToken()
}

// BuildAuthCodeURL builds the authorization URL for the OAuth2 flow
func BuildAuthCodeURL(config *oauth2.Config, options ...Option) (string, error) {
	opts := NewOptions(options)
	var oauth2Options = []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("redirect_uri", opts.redirectURL),
	}
	// Add PKCE parameters only if PKCE is enabled
	if opts.usePKCE {
		if opts.codeVerifier == "" {
			return "", fmt.Errorf("code verifier is required for PKCE flow")
		}
		oauth2Options = append(oauth2Options,
			oauth2.SetAuthURLParam("code_challenge", GenerateCodeChallenge(opts.codeVerifier)),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
	}
	scopes := opts.Scopes(config.Scopes...)
	oauth2Options = append(oauth2Options, oauth2.SetAuthURLParam("scope", strings.Join(scopes, " ")))

	for paramName, paramValue := range opts.authURLParams {
		oauth2Options = append(oauth2Options, oauth2.SetAuthURLParam(paramName, paramValue))
	}
	URL := config.AuthCodeURL(opts.State(), oauth2Options...)
	return URL, nil
}

// Exchange exchanges the authorization code for an access token
func Exchange(ctx context.Context, config *oauth2.Config, code string, options ...Option) (*oauth2.Token, error) {
	opts := NewOptions(options)
	// Create exchange options
	exchangeOptions := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("redirect_uri", opts.redirectURL),
	}
	// Only include code_verifier for PKCE flow
	if opts.usePKCE {
		exchangeOptions = append(exchangeOptions,
			oauth2.SetAuthURLParam("code_verifier", opts.codeVerifier),
		)
	}

	tkn, err := config.Exchange(ctx, code, exchangeOptions...)
	if tkn == nil && err == nil {
		err = fmt.Errorf("failed to get token")
	}
	return tkn, err
}
