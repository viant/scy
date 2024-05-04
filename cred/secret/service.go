package secret

import (
	"context"
	"embed"
	"fmt"
	"github.com/viant/afs"
	"github.com/viant/scy"
	"github.com/viant/scy/cred"
	"os"
	"path"
	"strings"
	"sync"
)

// Service represents a secret service
type Service struct {
	baseDirectory string
	cache         map[string]*scy.Secret
	lock          *sync.RWMutex
	secrets       *scy.Service
	fs            afs.Service
	embedFS       *embed.FS
}

// GetCredentials returns credentials for supplied resource
func (s *Service) GetCredentials(ctx context.Context, resource string) (*cred.Generic, error) {
	secret, err := s.Lookup(ctx, Resource(resource))
	if err != nil {
		return nil, err
	}
	ret, ok := secret.Target.(*cred.Generic)
	if !ok {
		return nil, fmt.Errorf("unsupported secret type: %T, expected: %T", secret.Target, ret)
	}
	return ret, nil
}

func (s *Service) Lookup(ctx context.Context, secret Resource) (*scy.Secret, error) {
	s.lock.RLock()
	ret, ok := s.cache[secret.String()]
	s.lock.RUnlock()
	if ok {
		return ret, nil
	}
	res, err := secret.resource(ctx, s.fs, s.baseDirectory, s.embedFS)
	if err != nil {
		return nil, err
	}
	ret, err = s.secrets.Load(ctx, res)
	if err != nil {
		return nil, err
	}
	s.lock.Lock()
	s.cache[secret.String()] = ret
	s.lock.Unlock()
	return ret, nil
}

func (s *Service) ExpandSecret(ctx context.Context, input string, key Key, resource Resource) (string, error) {
	secret, err := s.Lookup(ctx, resource)
	if err != nil {
		return "", err
	}
	var pairs []string
	generic, ok := secret.Target.(*cred.Generic)
	if !ok {
		return "", fmt.Errorf("unsupported secret type: %T, expected: %T", secret.Target, generic)
	}
	holder := key.String()
	if value := generic.Username; value != "" {
		pairs = append(pairs, expandPairs(holder, "Username", value)...)
	}
	if value := generic.Email; value != "" {
		pairs = append(pairs, expandPairs(holder, "Email", value)...)
	}
	if value := generic.ClientEmail; value != "" {
		pairs = append(pairs, expandPairs(holder, "ClientEmail", value)...)
	}
	if value := generic.ProjectID; value != "" {
		pairs = append(pairs, expandPairs(holder, "ProjectID", value)...)
		pairs = append(pairs, expandPairs(holder, "ProjectId", value)...)
	}
	if value := generic.Password; value != "" {
		pairs = append(pairs, expandPairs(holder, "Password", value)...)
	}
	if value := generic.Endpoint; value != "" {
		pairs = append(pairs, expandPairs(holder, "Endpoint", value)...)
	}

	if value := secret.String(); len(value) > 0 {
		pairs = append(pairs, expandPairs(holder, "Data", value)...)
	}
	var replacer = strings.NewReplacer(pairs...)
	return replacer.Replace(input), nil
}

// Expand expands input credential keys with actual CredentialsFromLocation
func (s *Service) Expand(ctx context.Context, input string, secrets map[Key]Resource) (string, error) {
	if len(secrets) == 0 {
		return input, nil
	}
	var err error
	for k, v := range secrets {
		if strings.Contains(input, k.String()) {
			input, err = s.ExpandSecret(ctx, input, k, v)
			if err != nil {
				return "", err
			}
		}
	}
	return input, nil
}

func expandPairs(holder, key string, value string) []string {
	return []string{
		"${" + holder + "." + key + "}", value,
		"${" + holder + "." + strings.ToLower(key) + "}", value,
	}
}

func (s *Service) apply(options []Option) {
	for _, opt := range options {
		opt(s)
	}
	if s.baseDirectory == "" {
		s.baseDirectory = path.Join(os.Getenv("HOME"), ".secret")
	} else if strings.HasPrefix(s.baseDirectory, "~") {
		s.baseDirectory = strings.Replace(s.baseDirectory, "~", path.Join(os.Getenv("HOME"), ".secret"), 1)
	}
	if s.fs == nil {
		s.fs = afs.New()
	}
}

// New creates a new secret service
func New(opts ...Option) *Service {
	ret := &Service{
		cache:   make(map[string]*scy.Secret),
		lock:    &sync.RWMutex{},
		secrets: scy.New(),
	}
	ret.apply(opts)
	return ret
}
