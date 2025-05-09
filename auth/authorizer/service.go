package authorizer

import (
	"context"
	"fmt"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/flow"
	"github.com/viant/scy/cred"
	"golang.org/x/oauth2"
	"reflect"
)

// Service is a secretsService that provides authorization functionality
type Service struct {
	secretsService *scy.Service
}

// Command represents a command to authorize
type Command struct {
	AuthFlow  string         `json:"authFlow"`
	Config    *oauth2.Config `json:"config"`
	ConfigURL string         `json:"configURL"`

	Scopes     []string          `json:"scopes"`
	Secrets    map[string]string `json:"secrets"`
	SecretsURL string            `json:"secretsURL"`
	UsePKCE    bool              `json:"usePKCE"`
}



// Authorize authorizes a command using the provided context and command
func (s *Service) Authorize(ctx context.Context, command *Command) (*oauth2.Token, error) {
	err := s.ensureConfig(ctx, command)
	if err != nil {
		return nil, err
	}
	if command.SecretsURL != "" {
		err = s.ensureSecrets(ctx, command)
		if err != nil {
			return nil, err
		}
	}
	var authFlow flow.AuthFlow = flow.NewBrowserFlow()
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

func (s *Service) ensureConfig(ctx context.Context, command *Command) error {
	if command.ConfigURL != "" {
		resource := scy.EncodedResource(command.ConfigURL).Decode(ctx, reflect.TypeOf(cred.Oauth2Config{}))
		secret, err := s.secretsService.Load(ctx, resource)
		if err != nil {
			return fmt.Errorf("failed to load oauth2 config: %v", err)
		}
		configValue, ok := secret.Target.(*cred.Oauth2Config)
		if !ok {
			return fmt.Errorf("failed to cast secret to config, expected %T but had %T", &cred.Oauth2Config{}, secret.Target)
		}
		command.Config = &configValue.Config
	}
	return nil
}



func New() *Service {
	return &Service{secretsService: scy.New()}
}
