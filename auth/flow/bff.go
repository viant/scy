package flow

import (
	"context"
	"fmt"
	"github.com/viant/scy/auth/flow/browser"
	"github.com/viant/scy/auth/flow/endpoint"
	"net/url"
	"strings"
)

// AuthorizationExchangeHeader is the header name used to pass the authorization exchange information by backend for frontend flow
const AuthorizationExchangeHeader = "X-Authorization-Exchange"

type BackendForFrontendFlow interface {
	BeginAuthorization(ctx context.Context, authorizationURI string) (*AuthorizationExchange, error)
}

type BackendForFrontend struct{}

type AuthorizationExchange struct {
	Code        string
	RedirectURI string
	State       string
}

func (a *AuthorizationExchange) ToHeader() string {
	return fmt.Sprintf(`code=%q, state=%q, redirect_uri=%q`,
		a.Code,
		a.State,
		a.RedirectURI,
	)
}

func (a *AuthorizationExchange) FromHeader(header string) {
	parts := strings.Split(header, ",")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue // skip malformed segment
		}
		key := kv[0]
		val := strings.Trim(kv[1], `"`) // remove quotes
		switch key {
		case "code":
			a.Code = unescapeHeaderValue(val)
		case "redirect_uri":
			a.RedirectURI = unescapeHeaderValue(val)
		case "state":
			a.State = unescapeHeaderValue(val)
		}
	}
}

func unescapeHeaderValue(val string) string {
	return strings.ReplaceAll(val, `\"`, `"`)
}

func (b *BackendForFrontend) BeginAuthorization(ctx context.Context, authorizationURI string) (*AuthorizationExchange, error) {
	server, err := endpoint.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create server %v", err)
	}
	go server.Start()
	result := &AuthorizationExchange{}
	URL, err := url.Parse(authorizationURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authorizationURI %v", err)
	}
	result.State = URL.Query().Get("state")
	if result.State == "" {
		result.State = randomToken()
		authorizationURI += "&state=" + result.State
	}
	result.RedirectURI = fmt.Sprintf("http://localhost:%v/callback", server.Port)
	authorizationURI += "&redirect_uri=" + result.RedirectURI
	cmd := browser.Open(authorizationURI)
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
	result.Code = code
	return result, nil
}
