package gcp

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"os"
	"path"
)

//Client represents IAM GCP client
type Client struct {
	ID     string
	Secret string
	App    string
}

func (c *Client) localTokenURL() string {
	return path.Join(os.Getenv("HOME"), "."+c.App, c.ID+".json")
}

//Config creates oauth config
func (c *Client) Config(redirectURL string, scopes ...string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.ID,
		ClientSecret: c.Secret,
		Scopes:       scopes,
		RedirectURL:  redirectURL,
		Endpoint:     google.Endpoint,
	}
}
