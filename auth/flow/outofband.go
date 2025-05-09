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
	URL, err := buildAuthCodeURL(redirectURL, config, opts)
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


	// Create exchange options
	exchangeOptions := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("redirect_uri", redirectURL),
	}

	// Only include code_verifier for PKCE flow
	if opts.usePKCE {
		exchangeOptions = append(exchangeOptions, oauth2.SetAuthURLParam("code_verifier", opts.codeVerifier))
	}

	tkn, err := config.Exchange(ctx, code, exchangeOptions...)
	if tkn == nil && err == nil {
		err = fmt.Errorf("failed to get token")
	}
	return tkn, err
}

func NewOutOfBandFlow() *OutOfBandFlow {
	return &OutOfBandFlow{}
}
