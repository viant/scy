package scy

import (
	"fmt"
	"github.com/viant/afs/storage"
	"reflect"
	"time"
)

// Resource represents a secret config
type Resource struct {
	Name      string `json:",omitempty"`
	URL       string `json:",omitempty"`
	Key       string `json:",omitempty"` //encryption key
	MaxRetry  int    `json:",omitempty"`
	TimeoutMs int    `json:",omitempty"`
	Fallback  *Resource
	Options   []storage.Option
	Data      []byte
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
