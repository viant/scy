package authorizer

import (
	"context"
	"fmt"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/flow"
	"github.com/viant/scy/cred"
	"golang.org/x/oauth2"
	"net/http"
	"reflect"
)

// Service is a secretsService that provides authorization functionality
type Service struct {
	secretsService *scy.Service
}

type OAuthConfig struct {
	Config    *oauth2.Config `json:"config"`
	ConfigURL string         `json:"configURL"`
}

// Command represents a command to authorize
type Command struct {
	OAuthConfig
	AuthFlow    string                        `json:"authFlow"`
	Scopes      []string                      `json:"scopes"`
	Secrets     map[string]string             `json:"secrets"`
	SecretsURL  string                        `json:"secretsURL"`
	UsePKCE     bool                          `json:"usePKCE"`
	NewEndpoint func() (flow.Endpoint, error) `json:"-" yaml:"-"`
}

func (s *Service) EnsureConfig(ctx context.Context, config *OAuthConfig) error {
	if config.ConfigURL != "" {
		resource := scy.EncodedResource(config.ConfigURL).Decode(ctx, reflect.TypeOf(cred.Oauth2Config{}))
		secret, err := s.secretsService.Load(ctx, resource)
		if err != nil {
			return fmt.Errorf("failed to load oauth2 config: %v", err)
		}
		configValue, ok := secret.Target.(*cred.Oauth2Config)
		if !ok {
			return fmt.Errorf("failed to cast secret to config, expected %T but had %T", &cred.Oauth2Config{}, secret.Target)
		}
		config.Config = &configValue.Config
	}
	return nil
}

// IDClient returns identity token HTTP config
func (s *Service) IDClient(ctx context.Context, command *Command) (*http.Client, error) {
	token, err := s.Authorize(ctx, command)
	if err != nil {
		return nil, err
	}
	if idToken := token.Extra("id_token"); idToken != nil {
		token.AccessToken = idToken.(string)
	}
	return command.Config.Client(ctx, token), nil
}

// Authorize authorizes a command using the provided context and command
func (s *Service) Authorize(ctx context.Context, command *Command) (*oauth2.Token, error) {
	err := s.EnsureConfig(ctx, &command.OAuthConfig)
	if err != nil {
		return nil, err
	}
	if command.SecretsURL != "" {
		err = s.ensureSecrets(ctx, command)
		if err != nil {
			return nil, err
		}
	}
	var opts []flow.BrowserFlowOption
	if command.NewEndpoint != nil {
		opts = append(opts, flow.WithNewEndpoint(command.NewEndpoint))
	}
	var authFlow flow.AuthFlow = flow.NewBrowserFlow(opts...)
	switch command.AuthFlow {
	case "OOB":
		authFlow = flow.NewOutOfBandFlow()

	}
	return authFlow.Token(ctx, command.Config, flow.WithPKCE(command.UsePKCE), flow.WithScopes(command.Scopes...), flow.WithPostParams(command.Secrets))
}

func (s *Service) ensureSecrets(ctx context.Context, command *Command) error {
	resource := scy.EncodedResource(command.SecretsURL).Decode(ctx, reflect.TypeOf(cred.Basic{}))
	secret, err := s.secretsService.Load(ctx, resource)
	if err != nil {
		return fmt.Errorf("failed to load oauth2 config: %v", err)
	}
	basicAuth, ok := secret.Target.(*cred.Basic)
	if !ok {
		return fmt.Errorf("failed to cast secret to config, expected %T but had %T", &cred.Oauth2Config{}, secret.Target)
	}
	command.Secrets = map[string]string{
		"username": basicAuth.Username,
		"password": basicAuth.Password,
	}
	return nil
}

// RefreshToken refresh token using the provided context, refresh token, and config
func (s *Service) RefreshToken(ctx context.Context, refreshToken *oauth2.Token, config *OAuthConfig) (*oauth2.Token, error) {
	if err := s.EnsureConfig(ctx, config); err != nil {
		return nil, err
	}
	tokenSource := config.Config.TokenSource(ctx, refreshToken)
	return tokenSource.Token()
}

func New() *Service {
	return &Service{secretsService: scy.New()}
}
