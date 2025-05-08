package gcp

import (
	"bytes"
	"cloud.google.com/go/compute/metadata"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/viant/afs"
	"github.com/viant/afs/file"
	"github.com/viant/scy/auth"
	"github.com/viant/scy/auth/flow"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
	"math/rand"
	"net/http"
	"os"
	"path"
	"time"
)

type Service struct {
	config   *oauth2.Config
	fs       afs.Service
	authFlow flow.AuthFlow
}

func (s *Service) Config(scopes ...string) *oauth2.Config {
	config := *s.config
	config.Scopes = append(config.Scopes, scopes...)
	return &config
}

// AuthClient returns auth  HTTP config
func (s *Service) AuthClient(ctx context.Context, scopes ...string) (*http.Client, error) {
	client, _ := google.DefaultClient(ctx, scopes...)
	if client != nil {
		return client, nil
	}

	token, err := s.Auth(ctx, scopes...)
	if err != nil {
		return nil, err
	}
	oauth2Config := s.Config(scopes...)
	tokenSource := oauth2Config.TokenSource(ctx, &token.Token)
	return oauth2.NewClient(ctx, tokenSource), nil
}

// IDClient returns identity token HTTP config
func (s *Service) IDClient(ctx context.Context, audience string, scopes ...string) (*http.Client, error) {
	if len(scopes) == 0 {
		scopes = Scopes
	}
	token, err := s.IDToken(context.Background(), audience, scopes...)
	if err != nil {
		return nil, err
	}
	return s.Config(scopes...).Client(ctx, token), nil
}

func (s *Service) ProjectID(ctx context.Context) string {
	if credentials, _ := google.FindDefaultCredentials(ctx); credentials != nil {
		return credentials.ProjectID
	}
	if value := os.Getenv("GCP_PROJECT"); value != "" {
		return value
	}
	if value := os.Getenv("GCLOUD_PROJECT"); value != "" {
		return value
	}
	return ""
}

func (s *Service) IDToken(ctx context.Context, audience string, scopes ...string) (*oauth2.Token, error) {
	if len(scopes) == 0 {
		scopes = Scopes
	}
	if credentials, _ := google.FindDefaultCredentials(ctx, scopes...); credentials != nil {
		tknSource, err := idtoken.NewTokenSource(ctx, audience)
		if err != nil {
			return nil, err
		}
		return tknSource.Token()
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
	scopes = append(s.config.Scopes, scopes...)
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
	tkn, err := s.authFlow.Token(ctx, s.config, flow.WithScopes(scopes...))
	if err != nil {
		return nil, err
	}
	token := &auth.Token{Token: *tkn}
	token.PopulateIDToken()
	return token, nil
}

func (s *Service) storeToken(token *auth.Token) error {
	tokenURL := localTokenURL(s.config)
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}
	return s.fs.Upload(context.Background(), tokenURL, file.DefaultFileOsMode, bytes.NewReader(data))
}

func localTokenURL(config *oauth2.Config) string {
	return path.Join(os.Getenv("HOME"), ".gcloud", config.ClientID)
}

func (s *Service) loadCachedToken() (*auth.Token, error) {
	tokenURL := localTokenURL(s.config)
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

func New(config *oauth2.Config) *Service {
	return &Service{config: config, fs: afs.New(), authFlow: flow.NewBrowserFlow()}
}

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
