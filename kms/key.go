package kms

import (
	"context"
	"fmt"
	"github.com/viant/afs"
	"github.com/viant/afs/file"
	"github.com/viant/afs/url"
	"os"
	"strings"
)

//Key represents secret key
type Key struct {
	Raw    string
	Path   string
	Auth   string
	Scheme string
}

//Key returns key data
func (k *Key) Key(ctx context.Context, defaultValue []byte) ([]byte, error) {
	switch k.Auth {
	case "inline":
		return []byte(k.Path), nil
	case "default":
		return defaultValue, nil
	case "env":
		key := strings.Trim(k.Path, "/")
		keyData := os.Getenv(key)
		if keyData == "" {
			return nil, fmt.Errorf("env.key %v was empty", key)
		}
		if len(keyData) < 8 {
			return nil, fmt.Errorf("invalid key length, expected min: 8 but had %v", len(keyData))
		}
		return []byte(keyData), nil
	default:
		fs := afs.New()
		return fs.DownloadWithURL(ctx, k.Path)
	}
}

//NewKey creates a new key
func NewKey(raw string) (*Key, error) {
	scheme := url.Scheme(raw, file.Scheme)
	path := raw
	if strings.HasPrefix(raw, "projects/") {
		scheme = "gcp"
	}
	_, err := kms.lookup(scheme)
	if err != nil {
		return nil, err
	}
	if path = url.Path(raw); path == "" {
		path = raw
	}
	return &Key{
		Scheme: scheme,
		Raw:    raw,
		Auth:   url.Host(raw),
		Path:   path,
	}, nil
}
