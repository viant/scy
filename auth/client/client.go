package client

import (
	"golang.org/x/oauth2"
	"os"
	"path"
)

// Client represents IAM GCP client
type Client struct {
	ID       string
	Secret   string
	App      string
	Endpoint oauth2.Endpoint
}

func (c *Client) LocalTokenURL() string {
	return path.Join(os.Getenv("HOME"), "."+c.App, c.ID+".json")
}

// Config creates oauth config
func (c *Client) Config(redirectURL string, scopes ...string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.ID,
		ClientSecret: c.Secret,
		Scopes:       scopes,
		RedirectURL:  redirectURL,
		Endpoint:     c.Endpoint,
	}
}

func NewClient(id, secret, app string, endpoint oauth2.Endpoint) *Client {
	return &Client{
		ID:       id,
		Secret:   secret,
		App:      app,
		Endpoint: endpoint,
	}
}
