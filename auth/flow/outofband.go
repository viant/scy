package flow

import (
	"context"
	"fmt"
	"golang.org/x/oauth2"
	"strings"
)

type OutOfBandFlow struct{}

func (s *OutOfBandFlow) Token(ctx context.Context, config *oauth2.Config, options ...Option) (*oauth2.Token, error) {
	opts := NewOptions(options)
	codeVerifier := GenerateCodeVerifier()

	redirectURL := outOfBandRedirectURL(config)

	URL, err := BuildAuthCodeURL(config, append(options, WithRedirectURI(redirectURL), WithCodeVerifier(codeVerifier))...)
	if err != nil {
		return nil, err
	}
	resp, err := postFormData(URL, opts.postParams)
	if err != nil {
		return nil, fmt.Errorf("failed to post form data %v", err)
	}
	code, err := fetchCodeFromLocationHeader(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch code from location header %v", err)
	}
	return Exchange(ctx, config, code, append(options, WithCodeVerifier(codeVerifier), WithRedirectURI(redirectURL))...)
}

func outOfBandRedirectURL(config *oauth2.Config) string {
	if config != nil {
		if redirectURL := strings.TrimSpace(config.RedirectURL); redirectURL != "" {
			return redirectURL
		}
	}
	return "https://localhost/callback.html"
}

func NewOutOfBandFlow() *OutOfBandFlow {
	return &OutOfBandFlow{}
}
