package secret

import (
	"bytes"
	"context"
	"embed"
	"github.com/viant/afs"
	"github.com/viant/afs/storage"
	"github.com/viant/afs/url"
	"github.com/viant/scy"
	"github.com/viant/scy/cred"
	"os"
	"path"
	"strings"
)

// Secrets represents Secret to Location map
type Secrets map[Key]Resource

// NewSecrets creates new secrets
func NewSecrets(secrets map[string]string) Secrets {
	var result = make(map[Key]Resource)
	if len(secrets) == 0 {
		return result
	}
	for k, v := range secrets {
		result[Key(k)] = Resource(v)
	}
	return result
}

// Key represent secret key
type Key string

// String returns  secret key as string
func (s Key) String() string {
	return string(s)
}

// Resource represents a secret
type Resource string

func (r Resource) String() string {
	return string(r)
}

func (r Resource) URL() string {
	ret := string(r)
	if index := strings.Index(ret, "|"); index != -1 {
		return ret[:index]
	}
	return ret
}

func (r Resource) Key() string {
	ret := string(r)
	if index := strings.Index(ret, "|"); index != -1 {
		return ret[index+1:]
	}
	return ""
}

// Resource returns scy resource
func (r *Resource) resource(ctx context.Context, fs afs.Service, baseDir string, embedFS *embed.FS) (*scy.Resource, error) {
	URL := r.URL()

	if strings.HasPrefix(URL, "~") {
		URL = os.Getenv("HOME") + URL[1:]
	} else if strings.HasPrefix(URL, "/~") {
		URL = os.Getenv("HOME") + URL[2:]
	}

	if url.IsRelative(r.URL()) {
		locatedRelative := false
		if currentDir, _ := os.Getwd(); currentDir != "" {
			if loc := locateResource(ctx, fs, currentDir, URL); loc != "" {
				locatedRelative = true
				URL = loc
			}
		}
		if !locatedRelative {
			if loc := locateResource(ctx, fs, baseDir, URL); loc != "" {
				URL = loc
			}
		}
	}

	ensureExtension(ctx, fs, &URL, embedFS)
	key := r.Key()
	data, err := fs.DownloadWithURL(ctx, URL)
	if err != nil {
		return nil, err
	}
	if key == "" && bytes.Contains(data, []byte("Password")) { //ensure it is not plain text password
		key = "blowfish://default"
	}
	resource := scy.NewResource(&cred.Generic{}, URL, key)
	if embedFS != nil {
		resource.Options = append(resource.Options, embedFS)
	}
	return resource, nil
}

func ensureExtension(ctx context.Context, fs afs.Service, URL *string, embedFS *embed.FS) bool {
	if path.Ext(*URL) != "" {
		return false
	}
	var opts []storage.Option
	if embedFS != nil {
		opts = append(opts, embedFS)
	}
	if ok, _ := fs.Exists(ctx, *URL+".json", opts...); ok {
		*URL += ".json"
		return true
	}
	if embedFS == nil {
		return false
	}
	if ok, _ := fs.Exists(ctx, "embed:///"+*URL+".json", opts...); ok {
		*URL += ".json"
		return true
	}
	return false
}

func locateResource(ctx context.Context, fs afs.Service, baseDir string, URL string) string {
	candidate := url.Join(baseDir, URL)
	if ok, _ := fs.Exists(ctx, candidate); ok {
		return candidate
	}
	if ensureExtension(ctx, fs, &candidate, nil) {
		return candidate
	}
	return ""
}
