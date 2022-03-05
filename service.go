package scy

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/viant/afs"
	"github.com/viant/afs/file"
	"github.com/viant/scy/cred"
	"github.com/viant/scy/kms"
	"reflect"
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
	data, err := s.fs.DownloadWithURL(ctx, resource.URL)
	if err != nil {
		return nil, err
	}
	key, cipher, err := s.loadKeyCipher(resource.Key)
	if err != nil {
		return nil, err
	}
	secret := &Secret{
		Resource: resource,
		payload:  data,
	}
	if resource.Name == "" && resource.target == nil {
		if isJSON := json.Valid(data); isJSON {
			resource.target = reflect.TypeOf(cred.Generic{})
		}
	}
	shallDecipher := key != nil
	if resource.target != nil {
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
	}
	secret.IsPlain = !(bytes.HasPrefix(data, []byte{'{'}) && bytes.HasSuffix(data, []byte{'}'}))
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
