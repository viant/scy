package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/viant/scy/auth/firebase"
	"github.com/viant/scy/auth/gcp"
	"github.com/viant/scy/auth/gcp/client"
	"github.com/viant/scy/cred"
	"google.golang.org/api/option"
)

// AuthCmd command for authentication
type AuthCmd struct {
	TypedSource


	Firebase  bool   `short:"f" long:"firebase" description:"firebase"`
	Key       string `short:"k" long:"key" description:"key i.e blowfish://default"`
	ProjectId string `short:"p" long:"projectId" description:"project id"`
}

// Init normalizes file locations
func (a *AuthCmd) Init() {
	a.SourceURL = normalizeLocation(a.SourceURL)
}

// Validate validates the auth command options
func (a *AuthCmd) Validate() error {
	// No specific validation needed for auth command
	return nil
}

// Execute runs the auth command
func (a *AuthCmd) Execute(args []string) error {
	a.Init()
	return Auth(a)
}

// Auth handles authentication
func Auth(auth *AuthCmd) error {
	if auth.Firebase {
		return AuthFirebase(auth)
	}
	return fmt.Errorf("unsupported auth mode")
}




// AuthFirebase handles Firebase authentication
func AuthFirebase(auth *AuthCmd) error {
	auth.Target = "basic"
	secret, err := loadSecret(auth)
	if err != nil {
		return err
	}
	gcpService := gcp.New(client.NewScy())
	authorizer, err := newFirebaseAuthorizer(context.Background(), auth, gcpService)
	if err != nil {
		return err
	}
	basicCred := secret.Target.(*cred.Basic)
	token, err := authorizer.InitiateBasicAuth(context.Background(), basicCred.Username, basicCred.Password)
	if err != nil {
		return err
	}
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", data)
	return nil
}

// newFirebaseAuthorizer creates a new Firebase identity service
func newFirebaseAuthorizer(ctx context.Context, cmd interface{}, gcpService *gcp.Service) (*firebase.Service, error) {
	var opts []option.ClientOption
	cfg := &firebase.Config{}

	var projectId string
	switch v := cmd.(type) {
	case *AuthCmd:
		projectId = v.ProjectId
	case *VerifyJwtCmd:
		projectId = v.ProjectId
	}

	if gcpService.ProjectID(ctx) == "" {
		if projectId != "" {
			cfg.ProjectID = projectId
			opts = append(opts, option.WithQuotaProject(projectId))
		}
		tokenSource := gcpService.TokenSource("https://www.googleapis.com/auth/cloud-platform")
		opts = append(opts, option.WithTokenSource(tokenSource))
	}
	identity, err := firebase.New(ctx, cfg, opts...)
	return identity, err
}
