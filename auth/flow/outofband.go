package flow

import (
	"context"
	"fmt"
	"golang.org/x/oauth2"
)

type OutOfBandFlow struct{}

func (s *OutOfBandFlow) Token(ctx context.Context, config *oauth2.Config, options ...Option) (*oauth2.Token, error) {
	opts := NewOptions(options)
	redirectURL := "https://localhost/callback.html"
	URL, err := BuildAuthCodeURL(redirectURL, config, opts)
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
	return Exchange(ctx, config, code, append(options, WithCodeVerifier(opts.codeVerifier), WithRedirectURL(redirectURL))...)
}

func NewOutOfBandFlow() *OutOfBandFlow {
	return &OutOfBandFlow{}
}
