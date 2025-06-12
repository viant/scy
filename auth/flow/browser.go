package flow

import (
	"context"
	"fmt"
	"github.com/viant/scy/auth/flow/browser"
	"github.com/viant/scy/auth/flow/endpoint"
	"golang.org/x/oauth2"
)

type Endpoint interface {
	Start()
	Wait() error
	AuthCode() string
	RedirectURL() string
}

type BrowserFlow struct {
	NewEndpoint func() (Endpoint, error)
}

func (s *BrowserFlow) Token(ctx context.Context, config *oauth2.Config, options ...Option) (*oauth2.Token, error) {
	codeVerifier := GenerateCodeVerifier()
	server, err := s.NewEndpoint()
	if err != nil {
		return nil, fmt.Errorf("failed to create server %v", err)
	}
	go server.Start()

	//local server will wait for callback
	redirectURL := server.RedirectURL()

	URL, err := BuildAuthCodeURL(config, append(options, WithRedirectURI(redirectURL), WithCodeVerifier(codeVerifier))...)
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
	return Exchange(ctx, config, code, append(options, WithCodeVerifier(codeVerifier), WithRedirectURI(redirectURL))...)
}

// BrowserFlowOption represents browser flow
type BrowserFlowOption func(*BrowserFlow)

func WithNewEndpoint(newEndpoint func() (Endpoint, error)) BrowserFlowOption {
	return func(o *BrowserFlow) {
		if newEndpoint == nil {
			return
		}
		o.NewEndpoint = newEndpoint
	}
}

// NewBrowserFlow create new browser flow
func NewBrowserFlow(opts ...BrowserFlowOption) *BrowserFlow {
	ret := &BrowserFlow{
		NewEndpoint: func() (Endpoint, error) {
			return endpoint.New()
		},
	}
	for _, opt := range opts {
		opt(ret)
	}
	return ret
}
