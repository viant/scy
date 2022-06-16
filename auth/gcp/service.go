package gcp

import (
	"bytes"
	"cloud.google.com/go/compute/metadata"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/viant/afs"
	"github.com/viant/afs/file"
	"github.com/viant/scy/auth"
	"github.com/viant/scy/auth/browser"
	"github.com/viant/scy/auth/gcp/endpoint"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
	"math/rand"
	"net/http"
	"time"
)

type Service struct {
	client *Client
	fs     afs.Service
}

func (s *Service) Config(ctx context.Context, scopes ...string) *oauth2.Config {
	return s.client.Config("", scopes...)
}

//AuthClient returns auth  HTTP client
func (s *Service) AuthClient(ctx context.Context, scopes ...string) (*http.Client, error) {
	if client, _ := google.DefaultClient(ctx, scopes...); client != nil {
		return client, nil
	}
	token, err := s.Auth(ctx, scopes...)
	if err != nil {
		return nil, err
	}
	tokenSource := s.client.Config("", scopes...).TokenSource(ctx, &token.Token)
	return oauth2.NewClient(ctx, tokenSource), nil
}

//IDClient returns identity token HTTP client
func (s *Service) IDClient(ctx context.Context, audience string, scopes ...string) (*http.Client, error) {
	if len(scopes) == 0 {
		scopes = Scopes
	}
	token, err := s.IDToken(context.Background(), audience, scopes...)
	if err != nil {
		return nil, err
	}
	return s.Config(ctx, scopes...).Client(ctx, token), nil
}

func (s *Service) IDToken(ctx context.Context, audience string, scopes ...string) (*oauth2.Token, error) {
	if len(scopes) == 0 {
		scopes = Scopes
	}
	if credentials, _ := google.FindDefaultCredentials(ctx, scopes...); credentials != nil {
		tokenSource, err := idtoken.NewTokenSource(ctx, audience)
		if err != nil {
			return nil, err
		}
		return tokenSource.Token()
	}
	if metadata.OnGCE() {
		//try to use meta server
		return nil, fmt.Errorf("failed to acquite token on GCE")
	}
	token, err := s.Auth(ctx, scopes...)
	if err != nil {
		return nil, err
	}
	return token.IdentityToken()
}

func (s *Service) TokenSource(scopes ...string) oauth2.TokenSource {
	return newTokenSource(s, scopes...)
}

func (s *Service) Auth(ctx context.Context, scopes ...string) (*auth.Token, error) {
	if tokenSource, _ := google.DefaultTokenSource(ctx, scopes...); tokenSource != nil {
		tkn, err := tokenSource.Token()
		if err != nil {
			return nil, err
		}
		return &auth.Token{Token: *tkn}, nil
	}
	if metadata.OnGCE() {
		return nil, fmt.Errorf("failed to acquite token on GCE")
	}
	if token, _ := s.loadCachedToken(); token != nil {
		return token, nil
	}
	return s.tokenWithBrowserFlow(scopes)
}

func (s *Service) tokenWithBrowserFlow(scopes []string) (*auth.Token, error) {
	server, err := endpoint.New()
	if err != nil {
		return nil, errors.Wrapf(err, "failed start auth callback endpoint")
	}
	redirectURL := fmt.Sprintf("http://localhost:%v/auth.html", server.Port)
	config := s.client.Config(redirectURL, scopes...)
	go server.Start()
	state := randToken()
	URL := config.AuthCodeURL(state)
	cmd := browser.Open(URL)
	var cmdError error
	go func() {
		if cmdError = cmd.Start(); cmdError != nil {
			server.Close()
		}
	}()
	if err = server.Wait(); err != nil {
		return nil, errors.Wrap(err, "failed to handler auth")
	}

	code := server.AuthCode()
	if code == "" && cmdError != nil {
		return nil, err
	}
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	tkn, err := config.Exchange(context.TODO(), code)
	if err != nil {
		return nil, err
	}
	token := &auth.Token{Token: *tkn}
	token.PopulateIDToken()
	_ = s.storeToken(token)
	return token, nil
}

func (s *Service) storeToken(token *auth.Token) error {
	tokenURL := s.client.localTokenURL()
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}
	return s.fs.Upload(context.Background(), tokenURL, file.DefaultFileOsMode, bytes.NewReader(data))
}

func (s *Service) loadCachedToken() (*auth.Token, error) {
	tokenURL := s.client.localTokenURL()
	data, err := s.fs.DownloadWithURL(context.Background(), tokenURL)
	if err != nil {
		return nil, err
	}
	token := &auth.Token{}
	if err = json.Unmarshal(data, token); err != nil {
		return nil, err
	}
	if token.Expired(time.Now()) {

		return nil, nil
	}
	return token, nil
}

func New(client *Client) *Service {
	return &Service{client: client, fs: afs.New()}
}

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
