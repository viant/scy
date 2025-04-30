package client

import "golang.org/x/oauth2"

type Option func(c *oauth2.Config)

func WithScopes(scopes ...string) Option {
	return func(c *oauth2.Config) {
		c.Scopes = scopes
	}
}

func WithRedirectURL(url string) Option {
	return func(c *oauth2.Config) {
		c.RedirectURL = url
	}
}
