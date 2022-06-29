package scy

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/viant/afs"
	"github.com/viant/afs/file"
	"github.com/viant/scy/cred"
	"github.com/viant/scy/kms"
	"os"
	"reflect"
	"strings"
)

//Service represents secret service
type Service struct {
	fs afs.Service
}

//Store stores secret
func (s *Service) Store(ctx context.Context, secret *Secret) error {
	err := secret.Validate()
	if err != nil {
		return err
	}
	payload := secret.payload
	err = s.store(ctx, secret, err, payload)
	if err != nil {
		if secret.Resource.Fallback != nil {
			clone := *secret
			clone.Resource = secret.Resource.Fallback
			return s.Store(ctx, &clone)
		}
	}
	return err
}

func (s *Service) store(ctx context.Context, secret *Secret, err error, payload []byte) error {
	key, cipher, err := s.loadKeyCipher(secret.Key)
	if err != nil {
		return err
	}
	shallCipher := key != nil
	if secret.Target != nil {
		if securable, ok := secret.Target.(kms.Securable); ok {
			shallCipher = false
			if err = securable.Cipher(ctx, key); err != nil {
				return err
			}
		}
		if payload, err = json.Marshal(secret.Target); err != nil {
			return err
		}
	}
	if shallCipher {
		if payload, err = cipher.Encrypt(ctx, key, payload); err != nil {
			return err
		}
	}

	return s.fs.Upload(ctx, secret.URL, file.DefaultFileOsMode, bytes.NewReader(payload))
}

func (s *Service) loadKeyCipher(resourceKey string) (*kms.Key, kms.Cipher, error) {
	var key *kms.Key
	var cipher kms.Cipher
	var err error
	if resourceKey != "" {
		if key, err = kms.NewKey(resourceKey); err != nil {
			return nil, nil, err
		}
		if cipher, err = kms.Lookup(key.Scheme); err != nil {
			return nil, nil, err
		}
	}
	return key, cipher, nil
}

//Load loads secret
func (s *Service) Load(ctx context.Context, resource *Resource) (*Secret, error) {
	data := resource.Data
	secret, err := s.load(ctx, resource, data)
	if err != nil {
		if resource.Fallback != nil {
			return s.Load(ctx, resource.Fallback)
		}
	}
	return secret, err
}

func (s *Service) load(ctx context.Context, resource *Resource, data []byte) (*Secret, error) {
	if len(resource.Data) == 0 {
		if strings.HasPrefix(resource.URL, "~") {
			resource.URL = os.Getenv("HOME") + resource.URL[1:]
		} else if strings.HasPrefix(resource.URL, "/~") {
			resource.URL = os.Getenv("HOME") + resource.URL[2:]
		}
		var err error

		resource.Init()
		for i := 0; i < resource.MaxRetry; i++ {
			tCtx, cancel := context.WithTimeout(ctx, resource.Timeout())
			data, err = s.fs.DownloadWithURL(tCtx, resource.URL)
			cancel()
			if err == nil {
				break
			}
		}
		if err != nil {
			return nil, err
		}
	}

	key, cipher, err := s.loadKeyCipher(resource.Key)
	if err != nil {
		return nil, err
	}
	secret := &Secret{
		Resource: resource,
		payload:  data,
	}
	isJSON := json.Valid(data)
	if resource.Name == "" && resource.target == nil {
		if isJSON {
			resource.target = reflect.TypeOf(cred.Generic{})
		}
	}
	shallDecipher := key != nil
	if resource.target != nil && isJSON {
		value := reflect.New(resource.target).Interface()
		if err = secret.Decode(value); err != nil {
			return nil, err
		}
		if securable, ok := value.(kms.Securable); ok && key != nil {
			shallDecipher = false
			if err = securable.Decipher(ctx, key); err != nil {
				return nil, err
			}
		}
		secret.Target = value
	}
	if shallDecipher {
		if data, err = cipher.Decrypt(ctx, key, data); err != nil {
			return nil, err
		}
		if isJSON = json.Valid(data); isJSON {
			if resource.target != nil && isJSON {
				value := reflect.New(resource.target).Interface()
				if err = json.Unmarshal(data, value); err == nil {
					secret.Target = value
				}
			}
		}
	}
	secret.IsPlain = !isJSON
	secret.payload = data

	if secret.Target == nil {
		secret.Target = string(data)
	} else {
		secret.payload, _ = json.Marshal(secret.Target)
	}
	return secret, nil
}

//New creates a new secret service
func New() *Service {
	return &Service{fs: afs.New()}
}
