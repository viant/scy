package flow

import (
	"context"
	"fmt"
	"github.com/viant/scy/auth/flow/browser"
	"github.com/viant/scy/auth/flow/endpoint"
	"golang.org/x/oauth2"
)

type BrowserFlow struct{}

func (s *BrowserFlow) Token(ctx context.Context, config *oauth2.Config, options ...Option) (*oauth2.Token, error) {
	opts := NewOptions(options)
	server, err := endpoint.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create server %v", err)
	}
	go server.Start()

	//local server will wait for callback
	redirectURL := fmt.Sprintf("http://localhost:%v/callback", server.Port)

	URL, err := buildAuthCodeURL(redirectURL, config, opts)
	if err != nil {
		return nil, err
	}
	cmd := browser.Open(URL)

	if err = cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start browser %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()
	if err = server.Wait(); err != nil {
		return nil, fmt.Errorf("failed to handler auth %v", err)
	}
	code := server.AuthCode()
	if code == "" {
		return nil, fmt.Errorf("failed to find auth code")
	}

	// Create exchange options
	exchangeOptions := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("redirect_uri", redirectURL),
	}

	// Only include code_verifier for PKCE flow
	if opts.usePKCE {
		exchangeOptions = append(exchangeOptions,
			oauth2.SetAuthURLParam("code_verifier", opts.codeVerifier),
		)
	}

	config.Endpoint.AuthStyle = oauth2.AuthStyleInHeader

	tkn, err := config.Exchange(ctx, code, exchangeOptions...)
	if tkn == nil && err == nil {
		err = fmt.Errorf("failed to get token")
	}
	return tkn, err
}

func NewBrowserFlow() *BrowserFlow {
	return &BrowserFlow{}
}
