package scy

import (
	"context"
	"fmt"
	"github.com/viant/afs"
	"github.com/viant/afs/storage"
	"github.com/viant/afs/url"
	"os"
	"reflect"
	"strings"
	"time"
)

// Resource represents a secret config
type Resource struct {
	Name      string           `json:",omitempty"  yaml:"Name"`
	URL       string           `json:",omitempty" yaml:"URL"`
	Key       string           `json:",omitempty" yaml:"Key"` //encryption key
	MaxRetry  int              `json:",omitempty" yaml:"MaxRetry"`
	TimeoutMs int              `json:",omitempty" yaml:"TimeoutMs"`
	Fallback  *Resource        `json:",omitempty" yaml:"Fallback"`
	Options   []storage.Option `json:"-" yaml:"-"`
	Data      []byte           `json:",omitempty" yaml:"Data"`
	target    reflect.Type
}

func (r *Resource) Timeout() time.Duration {
	return time.Duration(r.TimeoutMs) * time.Millisecond
}

func (r *Resource) Init() {
	if r.MaxRetry == 0 {
		r.MaxRetry = 3
	}
	if r.TimeoutMs == 0 {
		r.TimeoutMs = 5000
	}
}

// SetTarget sets target type
func (r *Resource) SetTarget(t reflect.Type) {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	r.target = t
}

// Validate checks if resource if valid
func (r *Resource) Validate() error {
	if r == nil {
		return fmt.Errorf("resource was empty")
	}
	if r.URL == "" {
		return fmt.Errorf("url was empty")
	}
	return nil
}

// NewResource creates a resource
func NewResource(target interface{}, URL, Key string) *Resource {
	result := &Resource{
		URL: URL,
		Key: Key,
	}
	if target == nil {
		return result
	}
	switch v := target.(type) {
	case string:
		result.Name = v
	case reflect.Type:
		result.SetTarget(v)
	default:
		result.SetTarget(reflect.TypeOf(v))
	}
	return result
}

// EncodedResource is a string that encodes a resource
type EncodedResource string

func (e EncodedResource) Decode(ctx context.Context, target interface{}) *Resource {
	URL := string(e)
	key := ""
	if index := strings.Index(URL, "|"); index != -1 {
		key = URL[index+1:]
		URL = URL[:index]
	}
	if url.IsRelative(URL) { //try to resolve relative URL
		fs := afs.New()
		candidate := url.Join(os.Getenv("HOME"), ".secret", URL)
		if ok, _ := fs.Exists(ctx, candidate); ok {
			URL = candidate
		}
	}
	return NewResource(target, URL, key)
}
