package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/viant/scy/auth/authorizer"
)

// AuthorizeCmd command for authorization
type AuthorizeCmd struct {
	AuthFlow   string   `short:"a" long:"authFlow" description:"authentication flow (Browser or OOB)" choice:"OOB" choice:"Browser" `
	ConfigURL  string   `short:"c" long:"configURL" description:"OAuth2 config URL"`
	SecretsURL string   `short:"e" long:"secretsURL" description:"secrets URL for username/password"`
	Scopes     []string `short:"s" long:"scopes" description:"OAuth2 scopes"`
	UsePKCE    bool     `short:"p" long:"usePKCE" description:"use PKCE for OAuth2 flow"`
	Key        string   `short:"k" long:"key" description:"key i.e blowfish://default"`
}

// Init normalizes file locations
func (a *AuthorizeCmd) Init() {
	a.ConfigURL = normalizeLocation(a.ConfigURL)
	a.SecretsURL = normalizeLocation(a.SecretsURL)
}

// Validate validates the authorize command options
func (a *AuthorizeCmd) Validate() error {
	return nil
}

// Execute runs the authorize command
func (a *AuthorizeCmd) Execute(args []string) error {
	a.Init()
	if err := a.Validate(); err != nil {
		return err
	}
	return Authorize(a)
}

// Authorize handles authorization
func Authorize(auth *AuthorizeCmd) error {
	service := authorizer.New()

	if auth.Key != "" {
		auth.ConfigURL += "|" + auth.Key
		auth.SecretsURL += "|" + auth.Key

	}

	command := &authorizer.Command{
		AuthFlow:   auth.AuthFlow,
		ConfigURL:  auth.ConfigURL,
		SecretsURL: auth.SecretsURL,
		Scopes:     auth.Scopes,
		UsePKCE:    auth.UsePKCE,
	}

	token, err := service.Authorize(context.Background(), command)
	if err != nil {
		return fmt.Errorf("authorization failed: %v", err)
	}

	// Print the token as JSON
	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal token: %v", err)
	}
	fmt.Printf("%s\n", data)

	// Also print the access token for easy copying
	fmt.Printf("\nAccess Token: %s\n", token.AccessToken)

	return nil
}
