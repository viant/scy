package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/viant/afs"
	"github.com/viant/afs/file"
	"github.com/viant/scy/auth"
	"github.com/viant/scy/auth/browser"
	"github.com/viant/scy/auth/endpoint"
	"golang.org/x/oauth2"
	"strings"
)

type Service struct {
	client *Client
	fs     afs.Service
}

func (s *Service) TokenWithBrowserFlow(scopes ...string) (*auth.Token, error) {
	server, err := endpoint.New()
	if err != nil {
		return nil, fmt.Errorf("failed start auth callback endpoint %v", err)
	}
	redirectURL := fmt.Sprintf("http://localhost:%v/auth.html", server.Port)

	fmt.Printf("redirectURL: %v\n", redirectURL)
	config := s.client.Config(redirectURL, scopes...)
	go server.Start()
	state := randToken()

	codeVerifier := randToken()
	codeChallenge := generateCodeChallenge(codeVerifier)
	URL := config.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("redirect_uri", redirectURL),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))

	cmd := browser.Open(URL)
	var cmdError error
	go func() {
		if cmdError = cmd.Start(); cmdError != nil {
			server.Close()
		}
	}()
	if err = server.Wait(); err != nil {
		return nil, fmt.Errorf("failed to handler auth %v", err)
	}

	code := server.AuthCode()
	if code == "" && cmdError != nil {
		return nil, err
	}
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	tkn, err := config.Exchange(context.Background(), code,
		oauth2.SetAuthURLParam("scope", strings.Join(scopes, ",")),
		oauth2.SetAuthURLParam("state", state),
		oauth2.SetAuthURLParam("grant_type", "authorization_code"),
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, err
	}
	token := &auth.Token{Token: *tkn}
	token.PopulateIDToken()
	_ = s.storeToken(token)
	return token, nil
}

func (s *Service) storeToken(token *auth.Token) error {
	tokenURL := s.client.LocalTokenURL()
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}
	return s.fs.Upload(context.Background(), tokenURL, file.DefaultFileOsMode, bytes.NewReader(data))
}

func New(client *Client) *Service {
	return &Service{
		client: client,
		fs:     afs.New(),
	}
}
