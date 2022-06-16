package gcp

import (
	"context"
	"golang.org/x/oauth2"
)

type tokenSource struct {
	*Service
	scopes []string
}

func (t *tokenSource) Token() (*oauth2.Token, error) {
	gcpScopes := append(t.scopes, Scopes...)
	token, err := t.Auth(context.Background(), gcpScopes...)
	if err != nil {
		return nil, err
	}
	return &token.Token, nil
}

func newTokenSource(srv *Service, scopes ...string) *tokenSource {
	return &tokenSource{
		Service: srv,
		scopes:  scopes,
	}
}
